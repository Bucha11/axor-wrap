"""Each agent's tool vocabulary, put in the kernel's terms.

The governor reasons over generic tool names (``bash``, ``read``, ``write``,
``web_fetch``) and declared roles (an untrusted source, an egress sink, an
instruction-following sink). Claude Code says ``Read(file_path=…)`` and
``WebFetch(url=…)``; Codex says ``Bash(command=…)`` and ``apply_patch``. This
module maps both onto one vocabulary, so the two agents are judged by the same
rules — and a value one of them fetched is recognised when the other one
carries it.
"""
from __future__ import annotations

import re

# roles of the canonical tools, as the governor is told them
UNTRUSTED_SOURCES = frozenset({"web_fetch", "web_search", "mcp_tool"})
EGRESS_SINKS = frozenset({"web_fetch"})
IMPERATIVE_SINKS = frozenset({"delegate"})
BENIGN_TOOLS = frozenset({"read", "glob", "grep", "todo"})
DRIVING_ARGS = {"web_fetch": ["url"], "delegate": ["prompt"]}

_PATCH_FILE = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$", re.MULTILINE)


def _path(args: dict) -> str:
    for key in ("file_path", "path", "notebook_path", "filename"):
        v = args.get(key)
        if isinstance(v, str) and v:
            return v
    return ""


def canonical(agent: str, tool: str, args: dict) -> tuple[str, dict]:
    """(tool, args) as the governor should see them. The raw call is what the
    trace records; this is only what the gates read."""
    args = args or {}
    name = tool.strip()
    low = name.lower()
    if low.startswith("mcp__"):
        return "mcp_tool", dict(args)
    if low in ("bash", "shell", "exec_command", "local_shell", "unified_exec"):
        cmd = args.get("command") or args.get("cmd") or ""
        if isinstance(cmd, list):
            cmd = " ".join(str(c) for c in cmd)
        return "bash", {"command": str(cmd)}
    if low == "apply_patch":
        patch = str(args.get("command") or args.get("input") or args.get("patch") or "")
        files = _PATCH_FILE.findall(patch)
        return "write", {"path": files[0] if files else "", "content": patch}
    if low in ("write", "edit", "multiedit", "notebookedit"):
        content = args.get("content") or args.get("new_string") or args.get("new_source") or ""
        if not content and isinstance(args.get("edits"), list):
            content = "\n".join(str(e.get("new_string", "")) for e in args["edits"]
                                if isinstance(e, dict))
        return "write", {"path": _path(args), "content": str(content)}
    if low == "read":
        return "read", {"path": _path(args)}
    if low in ("glob", "grep", "ls"):
        out = {"pattern": str(args.get("pattern") or "")}
        if args.get("path"):
            out["path"] = str(args["path"])
        return ("glob" if low == "glob" else "grep"), out
    if low == "webfetch":
        return "web_fetch", {"url": str(args.get("url") or "")}
    if low == "websearch":
        return "web_search", {"query": str(args.get("query") or "")}
    if low in ("task", "agent", "spawn_agent"):
        prompt = args.get("prompt") or args.get("message") or args.get("task") or ""
        return "delegate", {"prompt": str(prompt)}
    if low in ("todowrite", "update_plan"):
        return "todo", {}
    return low, dict(args)
