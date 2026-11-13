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
BENIGN_TOOLS = frozenset({"read", "glob", "grep", "todo", "axor_context"})
# the tree's own context server: a read, whose provenance its answer states
CONTEXT_SERVER = "axor_context"
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
    if low.startswith(f"mcp__{CONTEXT_SERVER}__"):
        return CONTEXT_SERVER, dict(args)
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


# ── read-only nodes ───────────────────────────────────────────────────────────
# A reader in a tree may look, never change. Its CLI is started read-only where
# the CLI can be (codex --sandbox read-only, claude --disallowedTools), and the
# hook holds the line as well: a write tool is refused, and a shell command
# runs only if every command in it is one that reads.
_READ_COMMANDS = frozenset({
    "cat", "head", "tail", "less", "more", "nl", "wc", "rg", "grep", "egrep", "fgrep",
    "ag", "ls", "tree", "find", "fd", "file", "stat", "pwd", "echo", "printf", "jq",
    "sort", "uniq", "cut", "tr", "diff", "basename", "dirname", "realpath",
    "which", "sed", "true", "test", "[", "cd", "bat", "python3", "python",
})
_GIT_READ = frozenset({"log", "diff", "show", "status", "grep", "blame", "ls-files",
                       "rev-parse", "branch", "tag", "describe", "shortlog"})
_FIND_WRITES = frozenset({"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint",
                          "-fprintf", "-fls"})


def read_only_command(command: str) -> bool:
    """Whether every command in a shell line only reads. Redirections into a
    file, ``sed -i``, ``find -delete``/``-exec`` and any command not known to
    read are refused; anything unparseable is refused."""
    import shlex

    if re.search(r"(^|[^<>&0-9])>{1,2}(?!&)", command.replace("2>&1", "").replace(">/dev/null", "")):
        return False
    if "$(" in command or "`" in command:
        return False
    for chunk in re.split(r"&&|\|\||;|\||\n", command):
        try:
            words = shlex.split(chunk)
        except ValueError:
            return False
        if not words:
            continue
        head = words[0].rsplit("/", 1)[-1]
        if head == "git":
            sub = next((w for w in words[1:] if not w.startswith("-")), "")
            if sub not in _GIT_READ:
                return False
            continue
        if head not in _READ_COMMANDS:
            return False
        if head == "sed" and any(w.startswith("-i") or w == "--in-place" for w in words[1:]):
            return False
        if head == "find" and any(w in _FIND_WRITES for w in words[1:]):
            return False
        if head == "sort" and any(w == "-o" or w.startswith(("-o", "--output")) for w in words[1:]):
            return False
        if head == "uniq" and len([w for w in words[1:] if not w.startswith("-")]) > 1:
            return False  # uniq IN OUT writes OUT
        if head in ("python", "python3") and not (len(words) >= 2 and words[1] in ("-V", "--version")):
            return False
    return True


def read_only_refusal(tool: str, args: dict) -> str | None:
    """Why a canonical call is not allowed on a read-only node, or None."""
    if tool in ("write", "delegate"):
        return f"this node is read-only ({tool} is not reading)"
    if tool == "bash" and not read_only_command(str(args.get("command", ""))):
        return "this node is read-only, and this shell command is not known to only read"
    if tool == "mcp_tool":
        return "this node is read-only, and an MCP tool may change things"
    return None
