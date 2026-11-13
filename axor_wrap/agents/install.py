"""Write the hook configuration for an agent CLI.

Claude Code: ``.claude/settings.json`` in the project (``--user``:
``~/.claude/settings.json``). Codex: ``.codex/hooks.json`` (``--user``:
``~/.codex/hooks.json``) — Codex runs a project or changed hook only after it is
reviewed and trusted with ``/hooks``.

Idempotent: an existing axor hook is replaced, every other hook is kept.
"""
from __future__ import annotations

import json
import shlex
import shutil
import sys
from pathlib import Path

EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop", "SessionEnd")
# events that filter on a tool name take a matcher
_TOOL_EVENTS = ("PreToolUse", "PostToolUse")
_MARK = "axor_wrap.cli hook"


def hook_command(agent: str) -> str:
    """Absolute, so the hook works whatever PATH or virtualenv the agent runs
    with: this interpreter, this package."""
    return f"{shlex.quote(sys.executable)} -m axor_wrap.cli hook {agent}"


def config_path(agent: str, project: Path, user: bool) -> Path:
    home = Path.home()
    if agent == "claude-code":
        return (home if user else project) / ".claude" / "settings.json"
    if agent == "codex":
        return (home if user else project) / ".codex" / "hooks.json"
    raise ValueError(f"unknown agent {agent!r}")


def _ours(entry: dict) -> bool:
    return any(_MARK in str(h.get("command", "")) for h in entry.get("hooks", []) or [])


def install(agent: str, project: Path, *, user: bool = False,
            timeout: int = 30) -> Path:
    path = config_path(agent, project, user)
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    hooks = data.setdefault("hooks", {})
    command = hook_command(agent)
    for event in EVENTS:
        kept = [e for e in hooks.get(event, []) if not _ours(e)]
        entry: dict = {"hooks": [{"type": "command", "command": command,
                                  "timeout": timeout}]}
        if event in _TOOL_EVENTS:
            entry = {"matcher": "*", **entry}
        hooks[event] = kept + [entry]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def uninstall(agent: str, project: Path, *, user: bool = False) -> Path | None:
    path = config_path(agent, project, user)
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    hooks = data.get("hooks", {})
    for event in list(hooks):
        hooks[event] = [e for e in hooks[event] if not _ours(e)]
        if not hooks[event]:
            del hooks[event]
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def agent_on_path(agent: str) -> bool:
    return shutil.which("claude" if agent == "claude-code" else "codex") is not None
