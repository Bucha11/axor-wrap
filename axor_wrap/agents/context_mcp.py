"""``axor_context`` — the tree's context as an MCP server (stdio).

A node is handed a ranked, budgeted slice of what its ancestors produced; this
is how it pulls the rest. Two tools:

* ``search(query, limit)`` — items whose text, file or node match, one line each
* ``get(ref)`` — one item in full

Every answer carries ``provenance``: whether the item (or any result) is
untrusted. The sidecar reads that from the tool's response and marks the pull
as an untrusted read in the puller's session — so untrusted context reaches a
node only by an act its governor sees. Excised items are refused.

Run by the agent CLI: ``python -m axor_wrap.agents.context_mcp <store.json>``.
"""
from __future__ import annotations

import json
import sys
from typing import Any

from axor_wrap.agents.context import ContextStore

PROTOCOL = "2025-06-18"

TOOLS = [
    {"name": "search",
     "description": "Search what earlier nodes of this tree found (plan, findings, "
                    "answers). Returns refs with one line each; get(ref) for the whole item.",
     "inputSchema": {"type": "object", "properties": {
         "query": {"type": "string"}, "limit": {"type": "integer", "default": 10}},
         "required": ["query"]}},
    {"name": "get",
     "description": "One item of the tree's context in full, by ref (e.g. read#2/f3).",
     "inputSchema": {"type": "object", "properties": {"ref": {"type": "string"}},
                     "required": ["ref"]}},
]


def _search(store: ContextStore, query: str, limit: int) -> dict:
    from axor_core.policy.keyword_relevance import extract_query_keywords

    want = extract_query_keywords(query) or {query.lower()}
    scored = []
    for item in store.items.values():
        if item.excised:
            continue
        hay = f"{item.node} {item.file} {item.text}".lower()
        hits = sum(1 for w in want if w in hay)
        if hits:
            scored.append((hits, item))
    scored.sort(key=lambda p: -p[0])
    results = [{"ref": i.ref, "node": i.node, "kind": i.kind, "line": i.pointer(),
                "untrusted": i.untrusted} for _, i in scored[:max(1, limit)]]
    untrusted = any(r["untrusted"] for r in results)
    return {"results": results,
            "provenance": {"untrusted": untrusted,
                           "sources": sorted({s for _, i in scored[:limit] for s in i.sources})}}


def _get(store: ContextStore, ref: str) -> dict:
    item = store.items.get(ref)
    if item is None:
        return {"error": f"no item {ref!r}", "provenance": {"untrusted": False, "sources": []}}
    if item.excised:
        return {"error": f"{ref} was excised by an operator",
                "provenance": {"untrusted": False, "sources": []}}
    return {"ref": item.ref, "node": item.node, "kind": item.kind, "text": item.headline(),
            "file": item.file, "line": item.line,
            "provenance": {"untrusted": item.untrusted, "sources": item.sources}}


def handle(store_path: str, request: dict) -> dict | None:
    method = request.get("method")
    rid = request.get("id")
    if method == "initialize":
        result: Any = {"protocolVersion": PROTOCOL,
                       "capabilities": {"tools": {}},
                       "serverInfo": {"name": "axor_context", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        params = request.get("params") or {}
        args = params.get("arguments") or {}
        store = ContextStore.load(store_path)   # re-read: the tree moves on
        if params.get("name") == "search":
            body = _search(store, str(args.get("query", "")), int(args.get("limit", 10)))
        elif params.get("name") == "get":
            body = _get(store, str(args.get("ref", "")))
        else:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32601, "message": "unknown tool"}}
        result = {"content": [{"type": "text", "text": json.dumps(body, ensure_ascii=False)}],
                  "isError": "error" in body}
    elif rid is None:
        return None  # a notification
    else:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": f"unknown method {method}"}}
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("usage: python -m axor_wrap.agents.context_mcp <store.json>", file=sys.stderr)
        return 2
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            reply = handle(argv[0], json.loads(line))
        except Exception as exc:  # noqa: BLE001 - answer, never die mid-session
            reply = {"jsonrpc": "2.0", "id": None,
                     "error": {"code": -32603, "message": str(exc)}}
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
