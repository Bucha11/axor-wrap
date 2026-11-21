# Changelog

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
