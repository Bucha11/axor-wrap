"""The hook protocol of each agent CLI, read in and answered back.

Claude Code and Codex speak nearly the same protocol: one JSON object on stdin
(``session_id``, ``cwd``, ``hook_event_name``, ``tool_name``, ``tool_input``,
``tool_response`` …), and a PreToolUse hook denies with
``{"hookSpecificOutput": {"hookEventName": "PreToolUse",
"permissionDecision": "deny", "permissionDecisionReason": …}}`` on stdout. What
differs is the tool vocabulary (``taxonomy.py``) and where the config lives
(``install.py``).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

AGENTS = ("claude-code", "codex")

# hook_event_name → the sidecar's event kind
_KINDS = {
    "PreToolUse": "pre_tool",
    "PostToolUse": "post_tool",
    "UserPromptSubmit": "prompt",
    "Stop": "stop",
    "SubagentStop": "subagent_stop",
    "SessionStart": "session_start",
    "SessionEnd": "session_end",
}


@dataclass
class HookEvent:
    agent: str
    kind: str                       # pre_tool | post_tool | prompt | stop | …
    session_id: str
    cwd: str = ""
    tool: str = ""
    tool_input: dict = field(default_factory=dict)
    tool_response: Any = None
    tool_use_id: str = ""
    prompt: str = ""
    last_message: str = ""
    transcript_path: str = ""
    model: str = ""
    # set by an orchestrator that spawned this agent as a tree node
    node_id: str = ""
    parent_node: str = ""
    tree_run: str = ""
    role: str = ""
    access: str = ""            # "read" = a read-only node of a tree

    def to_wire(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_wire(cls, data: dict) -> HookEvent:
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)


def parse_event(agent: str, raw: str | dict, env: dict | None = None) -> HookEvent:
    """One hook invocation's stdin as a :class:`HookEvent`. ``env`` is the
    hook's environment: an orchestrator running this agent as a tree node says
    so there (AXOR_NODE_ID, AXOR_PARENT_NODE, AXOR_TREE_RUN, AXOR_ROLE,
    AXOR_ACCESS)."""
    if agent not in AGENTS:
        raise ValueError(f"unknown agent {agent!r} (one of {', '.join(AGENTS)})")
    data = json.loads(raw) if isinstance(raw, str) else dict(raw)
    env = env or {}
    tool_input = data.get("tool_input")
    return HookEvent(
        agent=agent,
        kind=_KINDS.get(str(data.get("hook_event_name", "")), "other"),
        session_id=str(data.get("session_id") or "unknown"),
        cwd=str(data.get("cwd") or ""),
        tool=str(data.get("tool_name") or ""),
        tool_input=tool_input if isinstance(tool_input, dict) else
        ({"input": tool_input} if tool_input is not None else {}),
        tool_response=data.get("tool_response"),
        tool_use_id=str(data.get("tool_use_id") or ""),
        prompt=str(data.get("prompt") or ""),
        last_message=str(data.get("last_assistant_message") or ""),
        transcript_path=str(data.get("transcript_path") or ""),
        model=str(data.get("model") or ""),
        node_id=env.get("AXOR_NODE_ID", ""),
        parent_node=env.get("AXOR_PARENT_NODE", ""),
        tree_run=env.get("AXOR_TREE_RUN", ""),
        role=env.get("AXOR_ROLE", ""),
        access=env.get("AXOR_ACCESS", ""),
    )


def render_decision(event: HookEvent, decision: dict) -> tuple[str, int]:
    """(stdout, exit code) answering the agent. Only a PreToolUse can be
    denied; every other event is answered with silence and exit 0 — the hook
    observes, it never breaks the agent."""
    if event.kind != "pre_tool" or decision.get("allow", True):
        note = decision.get("note")
        if event.kind == "pre_tool" and note:
            # a call let through in observe mode still tells the agent why the
            # kernel would have refused it
            return json.dumps({"hookSpecificOutput": {
                "hookEventName": "PreToolUse", "additionalContext": note}}), 0
        return "", 0
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": decision.get("reason") or "denied by axor",
    }}), 0
