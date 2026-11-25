"""``axor_pair`` — the agents of a pair, writing to each other (MCP, stdio).

Three tools, the same for Claude Code and Codex, so a Claude agent writes to a
Codex one and back:

* ``peers()`` — the sessions this agent may write to: another session of the
  same developer, or one joined by a pair session on the Control Plane
* ``send(to, text)`` — a message to a peer session's agent
* ``thread(peer)`` — the latest messages either way with one peer

This server only carries the call. Which session is calling is known to the
workspace sidecar, which saw the very same call a moment earlier in the agent's
PreToolUse hook; the sidecar sends, and attaches what its taint ledger found in
the text. So a message built from a web page leaves marked as web content, and
the receiving sidecar registers it so — on another machine, under another
provider. An answer arrives in the receiving agent beside its next tool result
(or, for Claude Code, before it stops).

Run by the agent CLI: ``python -m axor_wrap.agents.pair_mcp``.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

PROTOCOL = "2025-06-18"
SERVER = "axor_pair"

TOOLS = [
    {"name": "peers",
     "description": "The other coding-agent sessions you may message: another session of "
                    "your developer, or a teammate's session joined with yours by a pair "
                    "session. Each has a node_id, its agent (claude-code, codex), its task "
                    "title and whether it is live.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "send",
     "description": "Send a short message to another session's agent (a node_id from peers). "
                    "Use it to coordinate: say what you changed that affects them, ask what "
                    "they are changing, agree on an interface. A teammate's agent may get it "
                    "only once the teammate lets it through. Replies arrive in your context "
                    "beside a later tool result.",
     "inputSchema": {"type": "object", "properties": {
         "to": {"type": "string", "description": "the peer session's node_id"},
         "text": {"type": "string", "description": "the message, at most 2000 characters"}},
         "required": ["to", "text"]}},
    {"name": "thread",
     "description": "The latest messages either way between you and one peer session.",
     "inputSchema": {"type": "object", "properties": {
         "peer": {"type": "string", "description": "the peer session's node_id"}},
         "required": ["peer"]}},
]


def _relay(tool: str, args: dict) -> dict:
    """Ask the workspace sidecar to carry out the call it saw in the hook."""
    from axor_wrap.agents.client import _request, workspace_root
    from axor_wrap.agents.sidecar import socket_path

    root = workspace_root(os.getcwd())
    try:
        return _request(socket_path(root), {"op": "pair_call", "tool": tool, "args": args},
                        timeout=15.0)
    except Exception as exc:  # noqa: BLE001 - said to the agent, never raised
        return {"error": f"the axor sidecar for this workspace did not answer ({exc}) — "
                         f"is axor-wrap installed as this agent's hook?"}


def handle(request: dict, relay: Any = _relay) -> dict | None:  # noqa: ANN401
    method = request.get("method")
    rid = request.get("id")
    if rid is None:
        return None  # a notification
    if method == "initialize":
        result: dict = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                        "serverInfo": {"name": SERVER, "version": "1"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        params = request.get("params") or {}
        name = str(params.get("name", ""))
        if name not in {t["name"] for t in TOOLS}:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32601, "message": "unknown tool"}}
        answer = relay(name, dict(params.get("arguments") or {}))
        error = answer.get("error") if isinstance(answer, dict) else "no answer"
        text = (str(error) if error else
                json.dumps(answer.get("result"), indent=1, ensure_ascii=False))
        result = {"content": [{"type": "text", "text": text}], "isError": bool(error)}
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": f"unknown method {method}"}}
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def main(argv: list[str] | None = None) -> int:
    del argv
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError:
            continue
        answer = handle(request)
        if answer is not None:
            sys.stdout.write(json.dumps(answer) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
