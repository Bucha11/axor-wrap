"""A tree of coding agents under the kernel: planner → five readers → implementer."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from axor_wrap.agents.context import ContextStore
from axor_wrap.agents.tree import TreeSpecError, node_prompt, parse_tree, run_tree

FAKE = str(Path(__file__).parent / "fixtures" / "fake_agent.py")
PKG = str(Path(__file__).resolve().parents[1])


def spec(**over):
    cmd = [sys.executable, FAKE, "{prompt}"]
    tree = {"task": "Add rate limiting to the auth module", "nodes": {
        "plan": {"agent": "claude-code", "model": "claude-fable-5-2", "out": "plan",
                 "command": cmd},
        "read": {"agent": "codex", "model": "luna", "count": 5, "access": "read",
                 "shard": "plan.questions", "out": "findings", "command": cmd},
        "impl": {"agent": "claude-code", "model": "claude-opus-5-5", "command": cmd},
    }}
    tree.update(over)
    return parse_tree(tree)


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "auth.py").write_text("def login(): ...\n")
    sock = str(tmp_path / "side.sock")
    monkeypatch.setenv("AXOR_SIDECAR_SOCKET", sock)
    monkeypatch.setenv("AXOR_SIDECAR_IDLE", "20")
    monkeypatch.setenv("AXOR_PLANE_URL", "")
    monkeypatch.setenv("PYTHONPATH", PKG + os.pathsep + os.environ.get("PYTHONPATH", ""))
    yield str(tmp_path)
    subprocess.run(["pkill", "-f", "--", f"--socket {sock}"], check=False)
    time.sleep(0.1)


async def test_planner_readers_implementer(workspace) -> None:
    run = await run_tree(spec(), workspace)
    nodes = run.report["nodes"]
    assert [o["status"] for o in nodes["plan"]] == ["ok"]
    assert [o["status"] for o in nodes["read"]] == ["ok"] * 5

    # the tree, as the kernel's spawn events recorded it
    assert [s["role"] for s in run.spawned] == ["plan"] + ["read"] * 5 + ["impl"]
    assert {s["executor"] for s in run.spawned if s["role"] == "read"} == {"codex/luna"}
    assert all(s["parent_id"] == run.tree_run for s in run.spawned)

    readers = [json.loads(o["output"]) for o in nodes["read"]]
    # each reader's findings were checked against the file it actually read
    assert all(r["verified"] == 1 and r["unverified"] == 1 for r in readers)

    impl = json.loads(nodes["impl"][0]["output"])
    assert impl == {"saw_verified": True, "saw_unverified": True, "saw_plan": True}


async def test_readers_split_the_questions_and_cannot_write(workspace) -> None:
    run = await run_tree(spec(), workspace)
    # the raw answers are inside the checked findings' source: re-run the
    # reader view through the sidecar is not needed — the fake reports in "mine"
    import axor_wrap.agents.client as client

    root = client.workspace_root(workspace)
    reads = [s["child_id"] for s in run.spawned if s["role"] == "read"]
    reports = [client.node_report(root, n) for n in reads]
    assert all(r["known"] for r in reports)
    # every reader read src/auth.py through the shell, and none wrote
    assert all(any(c[0] == "bash" for c in r["calls"]) for r in reports)
    assert not any(c[0] == "write" for r in reports for c in r["calls"])


async def test_a_node_its_hooks_never_saw_hands_on_untrusted(workspace) -> None:
    """A CLI that ran without the hooks firing is ungoverned as far as anyone
    can tell: its answer is untrusted. It is not pushed to the next stage —
    not its plan, not its questions — only listed by ref, to pull on purpose."""
    silent = [sys.executable, "-c",
              "import json; print(json.dumps({'type':'result','result': json.dumps("
              "{'steps':['x'],'questions':['q0']})}))"]
    tree = spec()
    tree.node("plan").command = silent
    run = await run_tree(tree, workspace)
    assert run.report["nodes"]["plan"][0]["status"] == "ok"
    assert run.store.items["plan#0"].untrusted
    for i in range(5):
        flow = run.report["flow"][f"read#{i}"]
        assert flow["withheld"] == ["plan#0"] and flow["pushed"] == []
    # nothing of the plan reached a reader's task, so the readers ran
    assert all(o["status"] == "ok" for o in run.report["nodes"]["read"])


async def test_untrusted_content_pushed_anyway_is_stopped_by_the_kernel(workspace) -> None:
    """The layer under the flow: if a rewrite DID carry an untrusted answer into
    a task (here, forced), the spawn gate sees it in derived_from and denies."""
    from axor_wrap.agents import context as ctx

    silent = [sys.executable, "-c",
              "import json; print(json.dumps({'type':'result','result': json.dumps("
              "{'steps':['x'],'questions':['q0']})}))"]
    tree = spec()
    tree.node("plan").command = silent
    real = ctx.ContextStore.compose

    def leaky(self, nodes, focus, budget):
        out = real(self, nodes, focus, budget)
        out["pushed"] += out["withheld"]
        out["derived_from"] += [i.raw for i in out["withheld"]]
        return out

    ctx.ContextStore.compose = leaky
    try:
        run = await run_tree(tree, workspace)
    finally:
        ctx.ContextStore.compose = real
    assert all(o["status"] == "denied" for o in run.report["nodes"]["read"])


def test_specs_are_checked() -> None:
    with pytest.raises(TreeSpecError, match="waits for"):
        parse_tree({"task": "t", "nodes": {"a": {"agent": "codex", "after": ["b"]}}})
    with pytest.raises(TreeSpecError, match="count"):
        parse_tree({"task": "t", "nodes": {"a": {"agent": "codex", "count": 9}}})
    with pytest.raises(TreeSpecError, match="shard"):
        parse_tree({"task": "t", "nodes": {"a": {"agent": "codex"},
                                          "b": {"agent": "codex", "shard": "a.questions"}}})
    with pytest.raises(TreeSpecError, match="agent"):
        parse_tree({"task": "t", "nodes": {"a": {"agent": "cursor"}}})
    stages = spec().stages()
    assert [[n.name for n in s] for s in stages] == [["plan"], ["read"], ["impl"]]


def test_each_reader_gets_its_own_share_of_the_questions() -> None:
    tree = spec()
    store = ContextStore()
    store.add_answer("plan", 0, "plan", json.dumps(
        {"steps": ["s"], "questions": [f"q{i}" for i in range(7)]}))
    shares = [[line[2:] for line in node_prompt(tree, tree.node("read"), i, store)[0]
               .splitlines() if line.startswith("- q")] for i in range(5)]
    assert shares == [["q0", "q5"], ["q1", "q6"], ["q2"], ["q3"], ["q4"]]


async def test_an_operator_cut_from_the_plane_never_reaches_the_next_stage(workspace) -> None:
    from tests.test_context import _Excising

    plane = _Excising(["read#2"])
    run = await run_tree(spec(), workspace, plane=plane)
    assert run.report["excised"] == ["read#2/f0", "read#2/f1"]
    assert not any(r.startswith("read#2/") for r in run.report["flow"]["impl#0"]["pushed"])
