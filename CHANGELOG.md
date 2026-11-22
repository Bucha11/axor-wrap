# Changelog

## 0.3.1 — 2026-11-21

### Added

- **`axor-wrap connect <plane> --key <key>`** — connect a machine once. It
  checks the address and the key against the plane, then saves them in
  `~/.axor/connection.json` (readable by this user only). The sidecar,
  `skill share`, `skill try` and `tree run` read it; nothing has to be exported
  in a shell profile any more. `AXOR_PLANE_URL` / `AXOR_INGEST_KEY` still
  override it. `axor-wrap connect` alone says where the machine reports;
  `axor-wrap disconnect` forgets it.
- Commands that need a plane say how to connect instead of naming env vars.
- **Only what came from outside ships as outside text.** A tool result's
  source is the kernel's answer (`output_root_of`, or the same arming map on
  axor-core 0.13.0), not a guess from its arguments: a local command's output
  or the answer to a write no longer shows on the plane as text from outside.
- **A developer hears when their machine stops reporting.** `axor-wrap
  connect` checks the key with the plane; at session start, a key the plane
  refuses (the developer was removed, or the key revoked) is said to the person
  in Claude Code (`systemMessage`). The session stays protected locally.
- **A developer hears when the plan does not show their session.** Past the
  free plan (a second developer, a second agent family) the plane keeps a
  session but does not show or operate it; its answer to the session's profile
  says so, and the sidecar tells the person once, in Claude Code.

- **A skill's dangerous script is refused when the agent runs it.** A script
  is one call to Axor; its lines are now read before it runs. A script a skill
  ships (`.claude/skills/…`, `.codex/skills/…`) that downloads and runs code,
  reads secrets or sends data out is refused, naming the line — a dry run
  (`skill try`) is no longer how it gets to run. A repository that trusts its
  skills: `.axor/rules.json` `{"allow": ["skill_scripts"]}`.
- **Refusals in words.** A call refused because outside text drove it says
  where the text came from and that the developer can run the command
  themselves — not the kernel's gate sentence.

- **A session is named by what it was asked.** The developer's first request
  in a session goes to the plane as its title (the first 120 characters), so
  the screens list sessions as tasks instead of host-and-counter ids.
- `skill try` counts calls the way the Control Plane does: what ran and what
  was refused.

### Fixed

- **Tool results reach the plane again.** The sidecar daemon runs as
  `python -m axor_wrap.agents.sidecar`; a helper defined below its `__main__`
  guard did not exist there, so every tool result failed and only the calls
  were shown — never what came back, nor that it was text from outside.

## 0.3.0 — 2026-11-20

The first release since 0.2.1: it also carries 0.2.2, which was prepared but
never published. Needs `axor-core>=0.10.2,<0.14`.

### Upgrading

- **Run `axor-wrap agents install` again.** Claude Code now also gets a
  `SessionStart` hook, which is how a session receives the team's memory.
  Without it, memory still arrives on the first prompt.
- New environment variables:
  - `AXOR_TEAM_SKILLS=0` — this machine does not install team skills.
  - `AXOR_TEAM_MEMORY=0` — this machine's agents are not given the team's memory.
  - `AXOR_NOTES_TTL` — how often (seconds, default 3) the sidecar asks the
    plane for pair-session notes.
- The sidecar now writes into `~/.claude/skills` and `~/.codex/skills`: only
  folders carrying its marker (`.axor-team.json`), never a skill of yours with
  the same name.
- **axor-core 0.13 defaults to context integrity.** After an untrusted read, a
  value the agent writes is untrusted unless the user's task or the operator's
  allowlist gave it. Pass the user's prompt: `WrappedToolset(..., task=prompt)`,
  `wrap_callables(..., task=prompt)` or `toolset.register_task(prompt)` — or a
  recipient the user named is refused after the first untrusted read. The
  coding sidecar already registers every prompt.

### Added

- **Govern Claude Code and Codex through their hooks** (`axor-wrap agents
  install`): a workspace sidecar gates every tool call, ships it to the
  Control Plane, and refuses dangerous calls whoever asked for them.
- **Trees of coding agents** (`axor.tree.yaml`): roles per child, context
  flow ranked and budgeted, untrusted context only by pull; tree runs show on
  the Control Plane as they go. Mixing agent families in one tree needs a paid
  workspace.
- **Skills**: `axor-wrap skill check` reads a skill before you install it;
  `skill try` dry-runs an agent with it. A skill turned off for the team is
  refused by every sidecar.
- **Team skills**: `axor-wrap skill share` uploads a skill; once someone turns
  it on for the team, each sidecar installs it at that version, and removes it
  when it is turned off.
- **Pair sessions**: notes from people watching a session reach the agent as
  context after its next tool call. A note from a guest outside the team is
  treated as untrusted text.
- **Team memory**: the sidecar sends the repository a session runs in and what
  each call carries; at session start the agent is given the facts the team
  verified for that repository, and the plane is told what was given — even
  when it was nothing.
- **`WrappedToolset(task=…)`, `register_task`**, and `task=` on
  `wrap_callables` and `toolset_for_arm`: the user's task is a trusted origin
  under axor-core's context integrity. `toolset_for_arm` also trusts the
  scenario's inputs, exactly what Lab's replay trusts.
- **The sidecar gives the governor the repository as its workspace**
  (axor-core 0.13 `workdir`), so after a web read the agent can still edit its
  own files; only writes outside the repository are integrity sinks.
- **observe**: an admitted call ships before its result; a failed call is
  recorded; `timeout` and `empty_result` do not taint the answer; a
  `silent_fail` result carries no untrusted source.
- **Plane**: shared feeds and link for adapters that own their loop;
  `post_trace`, `post_reputation`, `post_ingest`, honesty experiments,
  `PlaneConnector.flush()`, `PlaneAdmission.posture()`.

### Fixed (from 0.2.2)

- **The operator's one-shot commands reach the agent**: `PlaneAdmission`
  implements axor-core's `ControlDirectives`, so a queued excision, a
  test-bench injection and a lowered call budget are handed to the kernel
  instead of staying in the queue.
