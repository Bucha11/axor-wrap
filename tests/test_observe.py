"""The shared plane feeds (axor_wrap.observe) and the background link."""
from __future__ import annotations

import asyncio

import pytest

from axor_wrap.observe import RunRecorder, reconstruct_claim, taint_source


def test_recorder_lines_keyed_by_call_id_and_shipped_once():
    rec = RunRecorder("n1")
    a = rec.begin_tool("c1", "fetch", {"url": "https://x.example/p"})
    rec.end_tool(a, "token abcdef123456")
    b = rec.begin_tool("c2", "send", {"body": "abcdef123456"})
    rec.end_tool(b, "sent")
    lines = rec.pending_lines()
    assert [ln["kind"] for ln in lines] == ["tool_call", "tool_result"] * 2
    assert lines[1]["payload"]["value_ref"] == "c1"
    assert lines[2]["payload"]["arg_refs"] == {"body": "c1"}
    assert rec.pending_lines() == []


def test_fault_rides_before_its_call():
    rec = RunRecorder("n1")
    r = rec.begin_tool("c1", "t", {})
    r.fault = {"tool": "t", "mode": "silent_fail", "seed": "s", "canary": ""}
    rec.end_tool(r, "x")
    assert [ln["kind"] for ln in rec.pending_lines()] == ["fault_injected", "tool_call", "tool_result"]


def test_claim_reconstruction_does_not_accuse_an_admission():
    assert reconstruct_claim(["a", "a"], "Done: 4.25%")["tools_succeeded"] == ["a"]
    assert reconstruct_claim(["a"], "I couldn't reach it.")["tools_succeeded"] == []
    assert reconstruct_claim(["a"], "  ")["tools_succeeded"] == []


def test_taint_source_by_locator():
    assert taint_source({"url": "https://a"}) == "web"
    assert taint_source({"path": "/x"}) == "file"
    assert taint_source({}) == "unknown_external"


def test_link_admission_polls_posture_on_the_callers_loop():
    pytest.importorskip("httpx")
    from axor_wrap.plane.link import PlaneLink

    link = PlaneLink("http://cp.invalid", "n1", start=False)
    link._poll = 0.01
    link.session.paused = True

    async def run():
        task = asyncio.create_task(link.await_admission())
        await asyncio.sleep(0.05)
        assert not task.done()
        link.session.paused = False
        return await asyncio.wait_for(task, 1)

    assert asyncio.run(run()) is True
    link.session.stopped = True
    assert asyncio.run(link.await_admission()) is False
    assert link.node_id == "n1"


def test_link_takes_an_experiment_once():
    pytest.importorskip("httpx")
    from axor_wrap.plane.link import PlaneLink

    link = PlaneLink("http://cp.invalid", "n1", start=False, test_bench=True)
    link.session.apply_snapshot(1, {"pending_experiment": {
        "id": "x", "faults": [{"tool": "t", "mode": "silent_fail"}]}})
    assert link.take_experiment()["faults"][0]["tool"] == "t"
    assert link.take_experiment() is None
