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
_TOOL_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure")


def events_for(agent: str) -> tuple[str, ...]:
    """The hook events an agent is given. Claude Code reports a failed call —
    a non-zero exit, a tool error — as PostToolUseFailure, not PostToolUse:
    without it a failing test run was never recorded at all. Codex runs its
    PostToolUse after a non-zero exit too, and has no such event. SessionStart
    brings the skills turned on for the team up to date before a session's
    first prompt; elsewhere the first tool call does it. SubagentStart / Stop
    draw a subagent (Claude Code's Agent tool) as a branch of its session."""
    return EVENTS + ("PostToolUseFailure", "SessionStart", "SubagentStart", "SubagentStop") \
        if agent == "claude-code" else EVENTS
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
    for event in events_for(agent):
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


# ── axor_pair: the MCP server agents of a pair write to each other through ────

MCP_NAME = "axor_pair"
_TOML_OPEN = f"# >>> {MCP_NAME} (axor-wrap)"
_TOML_CLOSE = f"# <<< {MCP_NAME} (axor-wrap)"


def mcp_command() -> tuple[str, list[str]]:
    return sys.executable, ["-m", "axor_wrap.agents.pair_mcp"]


def mcp_config_path(agent: str, project: Path, user: bool) -> Path:
    home = Path.home()
    if agent == "claude-code":
        # user scope lives in ~/.claude.json; a project's servers in .mcp.json
        return home / ".claude.json" if user else project / ".mcp.json"
    if agent == "codex":
        return (home if user else project) / ".codex" / "config.toml"
    raise ValueError(f"unknown agent {agent!r}")


def _strip_toml_block(text: str) -> str:
    start = text.find(_TOML_OPEN)
    end = text.find(_TOML_CLOSE)
    if start == -1 or end == -1 or end < start:
        return text
    return (text[:start].rstrip("\n") + "\n" + text[end + len(_TOML_CLOSE):].lstrip("\n")
            ).lstrip("\n")


def install_mcp(agent: str, project: Path, *, user: bool = False) -> Path:
    """Register axor_pair with the agent CLI. Idempotent; every other server
    is kept. A Codex config that already names ``mcp_servers.axor_pair`` by
    hand is left alone."""
    path = mcp_config_path(agent, project, user)
    command, args = mcp_command()
    path.parent.mkdir(parents=True, exist_ok=True)
    if agent == "claude-code":
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        data.setdefault("mcpServers", {})[MCP_NAME] = {
            "type": "stdio", "command": command, "args": args}
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return path
    text = _strip_toml_block(path.read_text(encoding="utf-8")) if path.exists() else ""
    if f"[mcp_servers.{MCP_NAME}]" in text:
        return path
    block = "\n".join([_TOML_OPEN, f"[mcp_servers.{MCP_NAME}]",
                       f"command = {json.dumps(command)}",
                       f"args = {json.dumps(args)}", _TOML_CLOSE, ""])
    path.write_text((text.rstrip("\n") + "\n\n" if text.strip() else "") + block,
                    encoding="utf-8")
    return path


def uninstall_mcp(agent: str, project: Path, *, user: bool = False) -> Path | None:
    path = mcp_config_path(agent, project, user)
    if not path.exists():
        return None
    if agent == "claude-code":
        data = json.loads(path.read_text(encoding="utf-8"))
        servers = data.get("mcpServers") or {}
        if MCP_NAME not in servers:
            return None
        del servers[MCP_NAME]
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return path
    text = path.read_text(encoding="utf-8")
    stripped = _strip_toml_block(text)
    if stripped == text:
        return None
    path.write_text(stripped, encoding="utf-8")
    return path
