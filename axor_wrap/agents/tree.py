"""A tree of coding agents, run under the kernel.

``axor.tree.yaml`` names the nodes — which agent, which model, how many, what
they may do, what they hand on::

    task: Add rate limiting to the auth module
    nodes:
      plan:
        agent: claude-code
        model: claude-fable-5-2
        out: plan                 # {"steps": [...], "questions": [...]}
      read:
        agent: codex
        model: luna
        count: 5                  # five readers, in parallel
        access: read              # look, never change
        shard: plan.questions     # each takes its share of the planner's questions
        out: findings             # checked against the files each one opened
      impl:
        agent: claude-code
        model: claude-opus-5-5
        after: [read]             # default: the node before it

Nothing here is a second orchestration engine. The tree runs as ONE governed
session whose root is a deterministic executor: for each stage it issues the
kernel's own ``spawn_child`` — a batch when a stage has several children — and
each node is a declared child role (axor_core.contracts.roles). So every child
is gated like any spawn (capability, role, model switch, taint of the task it is
handed, the parent's ceiling), the trace records the tree from the spawns, and a
reader's findings are checked by the kernel before the next stage sees them.
"""
from __future__ import annotations

import dataclasses
import json
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from axor_core.contracts.invokable import Invokable
from axor_core.contracts.result import ExecutorEvent, ExecutorEventKind

from axor_wrap.agents.events import AGENTS

OUTS = ("text", "plan", "findings")
MAX_COUNT = 8


class TreeSpecError(ValueError):
    pass


@dataclass
class NodeSpec:
    name: str
    agent: str
    model: str = ""
    count: int = 1
    access: str = "write"          # write | read
    out: str = "text"              # text | plan | findings
    after: list[str] = field(default_factory=list)
    prompt: str = ""
    shard: str = ""                # "<plan node>.questions"
    timeout: float = 1800.0
    command: list[str] | None = None


@dataclass
class TreeSpec:
    task: str
    nodes: list[NodeSpec]

    def node(self, name: str) -> NodeSpec:
        return next(n for n in self.nodes if n.name == name)

    def stages(self) -> list[list[NodeSpec]]:
        """Topological levels: a node runs in the first stage after all it
        waits for."""
        level: dict[str, int] = {}
        for node in self.nodes:  # declaration order is already dependency order
            level[node.name] = 1 + max((level[a] for a in node.after), default=-1)
        out: list[list[NodeSpec]] = [[] for _ in range(max(level.values()) + 1)]
        for node in self.nodes:
            out[level[node.name]].append(node)
        return out

    def ancestors(self, name: str) -> list[str]:
        seen: list[str] = []
        stack = list(self.node(name).after)
        while stack:
            a = stack.pop()
            if a not in seen:
                seen.append(a)
                stack += self.node(a).after
        return [n.name for n in self.nodes if n.name in seen]


def parse_tree(data: dict) -> TreeSpec:
    if not isinstance(data, dict) or not isinstance(data.get("task"), str) or not data["task"]:
        raise TreeSpecError("a tree needs a task (text)")
    raw_nodes = data.get("nodes")
    if not isinstance(raw_nodes, dict) or not raw_nodes:
        raise TreeSpecError("a tree needs nodes: {name: {agent: …}}")
    nodes: list[NodeSpec] = []
    previous = ""
    for name, raw in raw_nodes.items():
        if not isinstance(raw, dict):
            raise TreeSpecError(f"node {name!r} must be a mapping")
        unknown = set(raw) - {f.name for f in dataclasses.fields(NodeSpec)} - {"name"}
        if unknown:
            raise TreeSpecError(f"node {name!r}: unknown keys {sorted(unknown)}")
        after = raw.get("after", [previous] if previous else [])
        after = [after] if isinstance(after, str) else list(after)
        node = NodeSpec(
            name=str(name), agent=str(raw.get("agent", "")), model=str(raw.get("model", "")),
            count=int(raw.get("count", 1)), access=str(raw.get("access", "write")),
            out=str(raw.get("out", "text")), after=after, prompt=str(raw.get("prompt", "")),
            shard=str(raw.get("shard", "")), timeout=float(raw.get("timeout", 1800)),
            command=list(raw["command"]) if raw.get("command") else None,
        )
        _check(node, [n.name for n in nodes], nodes)
        nodes.append(node)
        previous = node.name
    return TreeSpec(task=data["task"], nodes=nodes)


def _check(node: NodeSpec, earlier: list[str], nodes: list[NodeSpec]) -> None:
    from axor_core.contracts.roles import ChildRole

    try:
        ChildRole(node.name)
    except ValueError as exc:
        raise TreeSpecError(str(exc)) from None
    if node.agent not in AGENTS and not node.command:
        raise TreeSpecError(f"node {node.name!r}: agent must be one of {', '.join(AGENTS)} "
                            "(or give a command)")
    if not 1 <= node.count <= MAX_COUNT:
        raise TreeSpecError(f"node {node.name!r}: count must be 1..{MAX_COUNT}")
    if node.access not in ("read", "write"):
        raise TreeSpecError(f"node {node.name!r}: access is read or write")
    if node.out not in OUTS:
        raise TreeSpecError(f"node {node.name!r}: out is one of {', '.join(OUTS)}")
    for a in node.after:
        if a not in earlier:
            raise TreeSpecError(f"node {node.name!r} waits for {a!r}, which is not "
                                "declared before it")
    if node.shard:
        source, _, key = node.shard.partition(".")
        if key != "questions" or source not in earlier or \
                next(n for n in nodes if n.name == source).out != "plan":
            raise TreeSpecError(f"node {node.name!r}: shard is '<plan node>.questions' "
                                "for a node declared before it with out: plan")


def load_tree(path: str | Path) -> TreeSpec:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise TreeSpecError("YAML trees need PyYAML (pip install pyyaml); "
                                "or write the tree as .json / .toml") from None
        data = yaml.safe_load(text)
    elif path.suffix == ".toml":
        import tomllib

        data = tomllib.loads(text)
    else:
        data = json.loads(text)
    return parse_tree(data)


# ── what each node is told ────────────────────────────────────────────────────

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


def merge_findings(answers: list[str]) -> list[dict]:
    """The readers' checked findings, one list: duplicates (same file, line and
    claim) folded, verified first."""
    merged: dict[tuple, dict] = {}
    for answer in answers:
        data = _json_object(answer) or {}
        for f in data.get("findings", []):
            if not isinstance(f, dict):
                continue
            key = (f.get("file"), f.get("line"), str(f.get("claim", "")).strip().lower())
            if key not in merged or (f.get("verified") and not merged[key].get("verified")):
                merged[key] = f
    return sorted(merged.values(), key=lambda f: (not f.get("verified"), str(f.get("file"))))


_PLAN_ASK = (
    "You are the planner. Do not change any file. Answer with one JSON object: "
    '{"steps": ["…"], "questions": ["…"]} — steps to implement the task, and '
    "questions to answer from the codebase before implementing (what to look up, "
    "where). Nothing outside the JSON.")
_FINDINGS_ASK = (
    "You are a reader. Investigate by reading the code; change nothing. Answer with "
    'one JSON object: {"findings": [{"claim": "…", "file": "path", "line": 0}]}. '
    "Only claim what you saw in a file you opened, and name that file — a finding "
    "naming a file you did not open is marked unverified.")


class Upstream:
    """What finished nodes produced, kept for the nodes after them."""

    def __init__(self) -> None:
        self.outputs: dict[str, list[dict]] = {}

    def answers(self, name: str) -> list[str]:
        return [o["output"] for o in self.outputs.get(name, []) if o.get("status") == "ok"]

    def plan(self, name: str) -> dict:
        for answer in self.answers(name):
            data = _json_object(answer)
            if data is not None:
                return data
        return {}


def node_prompt(spec: TreeSpec, node: NodeSpec, index: int, upstream: Upstream) -> str:
    parts = [f"Task: {spec.task}"]
    for name in spec.ancestors(node.name):
        a = spec.node(name)
        if a.out == "plan":
            plan = upstream.plan(name)
            if plan.get("steps"):
                parts.append("Plan:\n" + "\n".join(f"{i + 1}. {s}" for i, s in
                                                   enumerate(plan["steps"])))
        elif a.out == "findings":
            found = merge_findings(upstream.answers(name))
            if found:
                lines = []
                for f in found:
                    where = f"{f.get('file', '?')}:{f.get('line', '?')}"
                    mark = "verified" if f.get("verified") else \
                        f"UNVERIFIED — {f.get('why', 'not backed by a read')}"
                    lines.append(f"- [{mark}] {where} {f.get('claim', '')}")
                parts.append(f"Findings from {name} (verified = the reader opened that "
                             "file; do not rely on unverified ones without checking):\n"
                             + "\n".join(lines))
        else:
            answers = upstream.answers(name)
            if answers:
                parts.append(f"From {name}:\n" + "\n\n".join(answers))
        failed = [o for o in upstream.outputs.get(name, []) if o.get("status") != "ok"]
        if failed:
            parts.append(f"Note: {len(failed)} run(s) of {name} did not complete "
                         f"({failed[0].get('reason', 'failed')}).")
    if node.shard:
        source = node.shard.partition(".")[0]
        questions = [q for q in upstream.plan(source).get("questions", []) if isinstance(q, str)]
        mine = questions[index::node.count] if questions else []
        if mine:
            parts.append("Your questions:\n" + "\n".join(f"- {q}" for q in mine))
    if node.prompt:
        parts.append(node.prompt)
    if node.out == "plan":
        parts.append(_PLAN_ASK)
    elif node.out == "findings":
        parts.append(_FINDINGS_ASK)
    return "\n\n".join(parts)


# ── the root: issues the spawns ───────────────────────────────────────────────

class _Bus:
    def __init__(self) -> None:
        self.results: dict[str, Any] = {}

    def push(self, tool_use_id: str, result: Any) -> None:
        self.results[tool_use_id] = result


class TreeExecutor(Invokable):
    """The tree's root node. Deterministic: it decides nothing a model would —
    it issues each stage's spawns and passes results on."""

    def __init__(self, spec: TreeSpec) -> None:
        self.spec = spec
        self.upstream = Upstream()
        self._bus = _Bus()

    def get_bus(self) -> _Bus:
        return self._bus

    async def stream(self, envelope: Any) -> AsyncIterator[ExecutorEvent]:
        for k, stage in enumerate(self.spec.stages()):
            asked: list[tuple[NodeSpec, int]] = []
            children: list[dict] = []
            for node in stage:
                for i in range(node.count):
                    asked.append((node, i))
                    children.append({
                        "task": node_prompt(self.spec, node, i, self.upstream),
                        "role": node.name,
                        # The task is REWRITTEN from what came before (a plan
                        # parsed, findings merged), and a rewrite is not
                        # substring-faithful: the per-value ledger would lose
                        # the provenance. The answers it was built from ride
                        # along verbatim, so the spawn gate judges the task by
                        # what it was made of.
                        "derived_from": [a for name in self.spec.ancestors(node.name)
                                         for a in self.upstream.answers(name)],
                    })
            tid = f"stage-{k}"
            args = children[0] if len(children) == 1 else {"children": children}
            yield ExecutorEvent(kind=ExecutorEventKind.TOOL_USE,
                                payload={"tool": "spawn_child", "args": args,
                                         "tool_use_id": tid},
                                node_id=envelope.node_id)
            for (node, i), outcome in zip(asked, self._outcomes(tid, len(children))):
                self.upstream.outputs.setdefault(node.name, []).append({"index": i, **outcome})
        yield ExecutorEvent(kind=ExecutorEventKind.TEXT,
                            payload={"text": json.dumps(self.report())},
                            node_id=envelope.node_id)
        yield ExecutorEvent(kind=ExecutorEventKind.STOP, payload={"usage": {}},
                            node_id=envelope.node_id)

    def _outcomes(self, tid: str, n: int) -> list[dict]:
        result = self._bus.results.get(tid)
        if isinstance(result, dict) and isinstance(result.get("children"), list):
            return [{"status": c.get("status", "denied"),
                     **({"output": c["output"]} if "output" in c else
                        {"reason": c.get("reason", "")})}
                    for c in result["children"]]
        if isinstance(result, str):
            failed = result.startswith(("[child spawn denied", "[child failed",
                                        "[child spawn failed"))
            return [{"status": "failed", "reason": result} if failed
                    else {"status": "ok", "output": result}]
        # a denial dict, or nothing came back
        reason = (result or {}).get("reason") if isinstance(result, dict) else None
        return [{"status": "denied", "reason": reason or str(result)}] * n

    def report(self) -> dict:
        return {"task": self.spec.task, "nodes": self.upstream.outputs}


# ── running one ───────────────────────────────────────────────────────────────

@dataclass
class TreeRun:
    tree_run: str
    report: dict
    spawned: list[dict]
    session: Any = None


async def run_tree(spec: TreeSpec, workspace: str, *, report: Any = None,
                   start_sidecar: bool = True, plane: Any = None,
                   plane_url: str | None = None, env: dict | None = None) -> TreeRun:
    """Run ``spec`` in ``workspace``. ``report(node_id) -> dict`` is how the
    executors learn what each node did (default: ask the workspace sidecar).
    With ``plane_url`` the tree run is a Control-Plane node of its own, named
    for the run, and its spawns draw the tree there."""
    from axor_core import ChildRole, GovernedSession, presets
    from axor_core.capability.executor import CapabilityExecutor
    from axor_core.contracts.policy import ToolPolicy
    from axor_core.contracts.trace import ChildSpawnedEvent, TraceConfig
    from axor_core.federation import FederationGateway

    from axor_wrap.agents import client
    from axor_wrap.agents.runners import CliAgent

    root_dir = client.workspace_root(workspace)
    if start_sidecar:
        client.ensure_sidecar(root_dir)
    if any(n.agent == "codex" and not n.command for n in spec.nodes):
        from axor_wrap.agents.install import config_path, install

        if not config_path("codex", Path(root_dir), user=False).exists():
            install("codex", Path(root_dir))
    if report is None:
        def report(node_id: str) -> dict:
            return client.node_report(root_dir, node_id)

    tree_run = f"tree-{uuid.uuid4().hex[:8]}"
    owned = None
    if plane is None and plane_url:
        try:
            from axor_wrap.plane.link import PlaneLink

            plane = owned = PlaneLink(plane_url, tree_run)
        except Exception:  # noqa: BLE001 - the tree runs without a plane
            plane = None
    root_policy = dataclasses.replace(presets.get("federated"), name="tree:root",
                                      allow_model_switch=True, max_child_depth=1)
    read_policy = dataclasses.replace(
        root_policy, name="tree:read",
        tool_policy=ToolPolicy(allow_read=True, allow_write=False, allow_bash=True,
                               allow_search=True, allow_spawn=False))
    write_policy = dataclasses.replace(
        root_policy, name="tree:write",
        tool_policy=dataclasses.replace(root_policy.tool_policy, allow_spawn=False))
    roles = [
        ChildRole(
            node.name,
            executor=CliAgent(node.agent, node.model, workspace=root_dir, tree_run=tree_run,
                              role=node.name, read_only=node.access == "read",
                              command=node.command, timeout=node.timeout, report=report,
                              env=env),
            label=f"{node.agent}/{node.model}" if node.model else node.agent,
            policy=read_policy if node.access == "read" else write_policy,
            output="findings" if node.out == "findings" else "text",
        )
        for node in spec.nodes
    ]
    executor = TreeExecutor(spec)
    session = GovernedSession(
        executor=executor,
        capability_executor=CapabilityExecutor(),
        trace_config=TraceConfig(local_only=True, persist_inputs=False),
        child_roles=roles,
        max_parallel_children=max(sum(n.count for n in s) for s in spec.stages()),
        # in-process children run on this kernel: restore their per-value
        # provenance instead of re-minting every answer untrusted
        federation_gateway=FederationGateway(peers={}, compatible_kernels=set(),
                                             federated_domains=set()),
    )
    await session.run(spec.task, policy=root_policy)
    # the root is the tree run on the plane; its children are named by the
    # kernel's node ids, the same ids their hooks report under
    spawned = [
        {"child_id": e.child_node_id,
         "parent_id": tree_run if e.child_depth == 1 else e.node_id,
         "depth": e.child_depth, "role": e.role, "executor": e.executor_label}
        for t in session.all_traces() for e in t.events if isinstance(e, ChildSpawnedEvent)
    ]
    run = TreeRun(tree_run, executor.report(), spawned, session)
    if plane is not None:
        lines = [{"kind": "node_spawned",
                  "payload": {**s, "edge_kind": "delegation", "tree_run": tree_run}}
                 for s in spawned]
        lines.append({"kind": "claim", "payload": {"text": json.dumps(run.report)[:4000],
                                                   "structured": True}})
        plane.submit(lambda: plane.connector.post_trace(lines, tree_run))
    if owned is not None:
        owned.close()
    return run
