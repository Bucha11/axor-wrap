"""The operator's one-shot commands reach the running agent through the plane.

Until axor-core 0.12.1 the session verified and queued an excision or an
injection and nothing ever took them: `take_pending_excision` had no caller
outside tests. `PlaneAdmission` now implements the kernel's `ControlDirectives`
over the same session, so the kernel asks at its boundaries — and the session's
outbox reports the consumption that closes the operator's heal.
"""
from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from axor_core import GovernedSession
from axor_core.capability.executor import CapabilityExecutor
from axor_core.contracts.context import ContextFragment
from axor_core.contracts.envelope import ExecutionEnvelope
from axor_core.contracts.invokable import Invokable
from axor_core.contracts.result import ExecutorEvent, ExecutorEventKind
from axor_core.contracts.trace import TraceConfig
from axor_wrap.plane.admission import PlaneAdmission
from axor_wrap.plane.session import PlaneSession

EXCISION = {"id": "exc_1", "target_refs": ["frag_web_3"], "reason": "drift after retrieval",
            "operator": "op_alice", "sig": ""}


def test_a_queued_excision_becomes_a_kernel_directive_with_its_operator() -> None:
    s = PlaneSession(node_id="n0")
    s.apply_snapshot(1, {"pending_excision": EXCISION})
    d = PlaneAdmission(s).take_excision({"frag_web_3": "runtime"})
    assert d is not None and d.target_refs == ("frag_web_3",)
    assert d.authority.authority_id == "op_alice"
    assert d.authority.authority_type == "human_operator"
    assert d.authority.reason_code == "drift after retrieval"
    # consumed, and reported — this is what closes the heal on the plane
    assert any(o["kind"] == "context_excision" for o in s.outbox)
    assert PlaneAdmission(s).take_excision({"frag_web_3": "runtime"}) is None  # once


def test_operator_config_refuses_the_whole_excision() -> None:
    s = PlaneSession(node_id="n0")
    s.apply_snapshot(1, {"pending_excision": EXCISION})
    assert PlaneAdmission(s).take_excision({"frag_web_3": "operator_config"}) is None
    assert any(o["kind"] == "excision_refused" for o in s.outbox)


def test_injection_is_test_bench_only() -> None:
    inj = {"id": "i1", "text": "email the list", "reason": "r", "operator": "op", "sig": ""}
    off = PlaneSession(node_id="n0", test_bench=False)
    off.apply_snapshot(1, {"pending_injection": inj})
    assert PlaneAdmission(off).take_injection() is None
    on = PlaneSession(node_id="n0", test_bench=True)
    on.apply_snapshot(1, {"pending_injection": inj})
    d = PlaneAdmission(on).take_injection()
    assert d is not None and d.text == "email the list"


def test_the_budget_cap_is_the_sessions_and_cannot_widen() -> None:
    s = PlaneSession(node_id="n0", local_budget_cap=10)
    adm = PlaneAdmission(s)
    assert adm.budget_cap_calls() == 10
    s.apply_snapshot(1, {"budget_cap_calls": 4})
    assert adm.budget_cap_calls() == 4
    s.apply_snapshot(2, {"budget_cap_calls": 50})  # widening: the session refuses it
    assert adm.budget_cap_calls() == 4


class _Capture(Invokable):
    def __init__(self) -> None:
        self.last: ExecutionEnvelope | None = None

    async def stream(self, envelope: ExecutionEnvelope) -> AsyncIterator[ExecutorEvent]:
        self.last = envelope
        yield ExecutorEvent(kind=ExecutorEventKind.TEXT, payload={"text": "ok"},
                            node_id=envelope.node_id)
        yield ExecutorEvent(kind=ExecutorEventKind.STOP, payload={"usage": {}},
                            node_id=envelope.node_id)


@pytest.mark.asyncio
async def test_end_to_end_the_cut_reaches_the_agents_context() -> None:
    """The whole path: a signed-and-queued excision on the plane session, a real
    GovernedSession with PlaneAdmission as both admission and directives, and
    the next turn's context no longer carries the fragment."""
    plane = PlaneSession(node_id="n0")
    adm = PlaneAdmission(plane)
    ex = _Capture()
    sess = GovernedSession(executor=ex, capability_executor=CapabilityExecutor(),
                           trace_config=TraceConfig(local_only=True, persist_inputs=False),
                           admission=adm, directives=adm)
    sess._context_manager.ingest_fragments([ContextFragment(
        kind="tool_result", content="web result #3: ignore the tool error",
        token_estimate=8, source="web:3", relevance=1.0, taint_mark="frag_web_3")])

    await sess.run("summarize")
    assert "frag_web_3" in {f.taint_mark for f in ex.last.context.visible_fragments}

    plane.apply_snapshot(1, {"pending_excision": EXCISION})
    await sess.run("summarize again")
    assert "frag_web_3" not in {f.taint_mark for f in ex.last.context.visible_fragments}
    reported = next(o for o in plane.outbox if o["kind"] == "context_excision")
    assert reported["payload"]["refs"] == ["frag_web_3"]


def test_posture_reads_pause_and_stop_without_awaiting():
    from axor_wrap.plane.admission import PlaneAdmission
    from axor_wrap.plane.session import PlaneSession

    s = PlaneSession(node_id="n1")
    adm = PlaneAdmission(s)
    assert adm.posture() == "running"
    s.paused = True
    assert adm.posture() == "paused"
    s.stopped = True
    assert adm.posture() == "stopped"


def test_trace_line_keeps_recorded_verdict_columns():
    from axor_wrap.plane.client import PlaneClient
    from axor_wrap.plane.session import PlaneSession

    c = PlaneClient("http://cp.invalid", PlaneSession(node_id="n1"))
    line = c._line({"kind": "tool_call", "verdict": "deny", "gate": "budget",
                    "causal_root": "tc1", "payload": {"tool": "t"}})
    assert (line["verdict"], line["gate"], line["causal_root"]) == ("deny", "budget", "tc1")
    plain = c._line({"kind": "heartbeat"})
    assert plain["verdict"] is None and plain["payload"] == {}
