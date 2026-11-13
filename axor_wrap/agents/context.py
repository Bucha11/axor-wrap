"""What flows between the nodes of a tree, and how much.

Every finished node's answer is cut into ITEMS — the plan, each finding, each
text answer — each with a ref (``read#2/f3``), its node, and its provenance as
the root session's ledger sees it. A downstream node is not handed everything
its ancestors said. It is handed:

* what is relevant to ITS work first — ranked against its own focus (its
  prompt, its share of the planner's questions, the plan's steps), verified
  findings before unverified ones;
* within a token budget (``context_tokens``); what does not fit is listed as a
  one-line pointer the node can pull in full;
* nothing untrusted by push — an item carrying untrusted provenance (a node
  that read the web, or whose hooks never reported) is WITHHELD and listed by
  ref. Pulling it is an explicit tool call (the ``axor_context`` MCP server),
  which the sidecar marks as an untrusted read in the puller's session;
* nothing an operator excised from the Control Plane — gone from push and pull.

So context moves by reference, and untrusted context moves only by an act the
governor sees. The store is a JSON file next to the workspace sidecar's socket;
the MCP server reads it.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_CONTEXT_TOKENS = 8000


def tokens(text: str) -> int:
    return max(1, len(text) // 4)


@dataclass
class Item:
    ref: str
    node: str
    kind: str                    # plan | finding | text
    text: str
    file: str = ""
    line: Any = None
    verified: bool | None = None
    why: str = ""
    untrusted: bool = False
    sources: list = field(default_factory=list)
    excised: bool = False
    raw: str = ""                # the whole answer it was cut from (provenance)

    def headline(self) -> str:
        if self.kind == "finding":
            where = f"{self.file or '?'}:{self.line if self.line is not None else '?'}"
            mark = "verified" if self.verified else \
                f"UNVERIFIED — {self.why or 'not backed by a read'}"
            return f"[{mark}] {where} {self.text}"
        return self.text

    def pointer(self) -> str:
        head = self.headline().splitlines()[0] if self.headline() else ""
        return f"- {self.ref} ({self.kind}) {head[:100]}"


def _json_object(text: str) -> dict | None:
    decoder = json.JSONDecoder()
    found = None
    pos = text.find("{")
    while pos != -1:
        try:
            data, end = decoder.raw_decode(text, pos)
        except ValueError:
            pos = text.find("{", pos + 1)
            continue
        if isinstance(data, dict):
            found = data
        pos = text.find("{", end)
    return found


class ContextStore:
    """The tree run's items. ``provenance(text) -> (untrusted, sources)`` is the
    root session's ledger, asked per answer."""

    def __init__(self, path: str | None = None, provenance: Any = None) -> None:
        self.path = path
        self.items: dict[str, Item] = {}
        self._questions: dict[str, list[str]] = {}
        self._provenance = provenance or (lambda text: (False, []))

    # ── filling ──────────────────────────────────────────────────────────────

    def add_answer(self, node: str, index: int, out: str, answer: str) -> list[Item]:
        untrusted, sources = self._provenance(answer)
        base = f"{node}#{index}"
        made: list[Item] = []

        def put(item: Item) -> None:
            item.untrusted, item.sources, item.raw = untrusted, list(sources), answer
            self.items[item.ref] = item
            made.append(item)

        data = _json_object(answer) if out in ("plan", "findings") else None
        if out == "plan" and data is not None:
            steps = [s for s in data.get("steps", []) if isinstance(s, str)]
            put(Item(base, node, "plan",
                     "\n".join(f"{i + 1}. {s}" for i, s in enumerate(steps)) or answer))
            self._questions[node] = [q for q in data.get("questions", [])
                                     if isinstance(q, str)]
        elif out == "findings" and data is not None:
            for j, f in enumerate(data.get("findings", [])):
                if not isinstance(f, dict):
                    continue
                put(Item(f"{base}/f{j}", node, "finding", str(f.get("claim", "")),
                         file=str(f.get("file") or ""), line=f.get("line"),
                         verified=bool(f.get("verified")), why=str(f.get("why", ""))))
        else:
            put(Item(base, node, "text", answer))
        self.save()
        return made

    def questions(self, plan_node: str) -> list[str]:
        """The planner's questions, to share out among readers — instructions,
        so they are handed on only from a plan that is trusted and not cut. A
        withheld plan's questions are withheld with it."""
        plans = [i for i in self.items.values() if i.node == plan_node and i.kind == "plan"]
        if not plans or any(i.untrusted or i.excised for i in plans):
            return []
        return list(self._questions.get(plan_node, []))

    def excise(self, refs: list[str]) -> list[str]:
        """Operator excision: the items named (or every item under a named
        ``node#i``) are gone from push and pull. Returns the refs cut."""
        cut = []
        for ref in refs:
            for key, item in self.items.items():
                if key == ref or key.startswith(ref + "/"):
                    item.excised = True
                    cut.append(key)
        self.save()
        return cut

    def provenance_map(self) -> dict[str, str]:
        """For the plane's excision guard: every item is runtime context; the
        task is the operator's and cannot be cut."""
        refs = set(self.items) | {ref.split("/", 1)[0] for ref in self.items}
        # a whole answer ("read#2") is cuttable as well as one finding of it
        return {"task": "operator_config", **dict.fromkeys(sorted(refs), "runtime")}

    # ── what a node is handed ────────────────────────────────────────────────

    def compose(self, nodes: list[str], focus: str, budget: int) -> dict:
        """The context for a node whose ancestors are ``nodes``: pushed items
        (full text, ranked, within ``budget`` tokens), pointers for the rest,
        and what was withheld as untrusted. ``derived_from`` is every answer a
        pushed item was cut from — what the spawn gate must see."""
        from axor_core.policy.keyword_relevance import extract_query_keywords

        want = extract_query_keywords(focus)

        def score(item: Item) -> tuple:
            words = extract_query_keywords(f"{item.file} {item.text}")
            overlap = len(want & words) / (1 + len(words) ** 0.5)
            return (item.kind != "plan", not item.verified if item.kind == "finding" else 0,
                    -overlap)

        live = [i for i in self.items.values() if i.node in nodes and not i.excised]
        # five readers often find the same thing: one copy, the verified one
        seen: dict[tuple, Item] = {}
        for item in sorted(live, key=lambda i: not i.verified):
            if item.kind != "finding":
                continue
            key = (item.file, item.line, item.text.strip().lower())
            seen.setdefault(key, item)
        keep = {id(i) for i in seen.values()}
        live = [i for i in live if i.kind != "finding" or id(i) in keep]
        withheld = [i for i in live if i.untrusted]
        ranked = sorted((i for i in live if not i.untrusted), key=score)
        pushed: list[Item] = []
        pointers: list[Item] = []
        used = 0
        for item in ranked:
            cost = tokens(item.headline())
            if used + cost <= budget:
                pushed.append(item)
                used += cost
            else:
                pointers.append(item)
        return {"pushed": pushed, "pointers": pointers, "withheld": withheld,
                "derived_from": list(dict.fromkeys(i.raw for i in pushed)),
                "tokens": used}

    # ── persistence (for the MCP server) ─────────────────────────────────────

    def save(self) -> None:
        if not self.path:
            return
        tmp = f"{self.path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"items": [asdict(i) for i in self.items.values()]}, fh)
        os.replace(tmp, self.path)

    @classmethod
    def load(cls, path: str) -> ContextStore:
        store = cls(None)
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        for raw in data.get("items", []):
            item = Item(**raw)
            store.items[item.ref] = item
        return store
