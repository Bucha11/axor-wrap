"""Governing coding-agent CLIs — Claude Code, Codex — through their hooks.

Both CLIs run a command before and after every tool call and hand it the call
as JSON on stdin; the command may deny the call. ``axor-wrap hook <agent>`` is
that command. It forwards the event to a sidecar — one long-lived process per
workspace — which holds what a single hook invocation cannot: the kernel's
per-call governor for each agent session, ONE taint ledger shared by every
agent in the workspace, the run recorder, and the Control-Plane link.

    agent CLI ──hook──▶ axor-wrap hook ──unix socket──▶ sidecar
                                                         ├─ ToolCallGovernor per session
                                                         ├─ shared TaintEngine (workspace)
                                                         └─ PlaneLink per session → CP

``axor-wrap agents install claude-code|codex`` writes the hook configuration.
"""
from axor_wrap.agents.events import AGENTS, HookEvent, parse_event, render_decision

__all__ = ["AGENTS", "HookEvent", "parse_event", "render_decision"]
