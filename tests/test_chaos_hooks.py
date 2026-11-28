"""QA-500: a chaos test armed from the plane on a live coding agent is taken
by its hooks at the first call to the tool it names, breaks that call, and is
reported so the plane records a chaos run — or is refused, with why, so the
plane stops showing it armed."""
from __future__ import annotations

import asyncio
import sys
import types

import pytest

from axor_wrap.agents import parse_event
from axor_wrap.agents.sidecar import Sidecar

pytest.importorskip("httpx")


@pytest.fixture
def engine(monkeypatch):
    """axor-eval's fault engine when installed; else a stand-in that fails a
    tool the way its silent_fail does (CI installs no axor-eval)."""
    try:
        import axor_eval.deprivation.engine  # noqa: F401
        return
    except ImportError:
        pass

    class Record:
        def __init__(self, tool, mode):
            self.tool_name, self.mode, self.seed, self.canary = tool, mode, "s", ""

    class Engine:
        def __init__(self, seed=""):
            self.fault_log, self.rules = [], {}

        def register(self, tool, mode):
            self.rules[tool] = mode

        def wrap(self, tool, fn):
            def broken(*a, **k):
                self.fault_log.append(Record(tool, self.rules[tool]))
                return {"error": "tool_unavailable", "tool": tool}
            return broken

    mod = types.ModuleType("axor_eval.deprivation.engine")
    mod.ToolDeprivationEngine = Engine
    for name in ("axor_eval", "axor_eval.deprivation"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "axor_eval.deprivation.engine", mod)


def _car(test_bench: bool, mode: str = "silent_fail", tool: str = "Bash"):
    from axor_wrap.plane.link import PlaneLink

    link = PlaneLink("http://cp.invalid", "n1", start=False, test_bench=test_bench)
    link.session.apply_snapshot(1, {"pending_experiment": {
        "id": "exp_1", "faults": [{"tool": tool, "mode": mode}], "operator": "op"}})
    shipped: list = []

    async def post_trace(lines, run_id):
        shipped.extend(lines)

    link.connector.post_trace = post_trace
    link.submit = lambda fn: asyncio.run(fn())
    return Sidecar("/repo", enforce=True, link_factory=lambda n: link), link, shipped


def _ev(name: str, n: int, **kw) -> object:
    data = {"session_id": "s1", "cwd": "/repo", "hook_event_name": name, **kw}
    if name == "PreToolUse":
        data.update(tool_use_id=f"t{n}")
    return parse_event("claude-code", data)


def _read(car, n):
    return car.handle(_ev("PreToolUse", n, tool_name="Read", tool_input={"file_path": "a.py"}))


def _bash(car, n):
    return car.handle(_ev("PreToolUse", n, tool_name="Bash", tool_input={"command": "pytest -q"}))


def test_the_armed_tool_is_broken_at_its_next_call_and_reported(engine) -> None:
    car, link, shipped = _car(test_bench=True)
    assert _read(car, 0)["allow"] is True            # another tool: still waiting
    assert link.pending_experiment() is not None
    out = _bash(car, 1)
    assert out["allow"] is False and "tool_unavailable" in out["reason"]
    assert link.pending_experiment() is None
    acks = [e["payload"] for e in link.session.outbox if e["kind"] == "operator_intervention"]
    assert acks == [{"action": "experiment_armed", "id": "exp_1",
                     "faults": [{"tool": "Bash", "mode": "silent_fail"}], "operator": "op"}]
    fault = next(ln for ln in shipped if ln["kind"] == "fault_injected")["payload"]
    assert fault["tool"] == "Bash" and fault["mode"] == "silent_fail"
    result = next(ln for ln in shipped if ln["kind"] == "tool_result")
    assert result["payload"]["tool"] == "Bash" and result["payload"]["status"] == "error"
    car.handle(_ev("Stop", 2, last_assistant_message="All tests pass."))
    claim = next(ln for ln in shipped if ln["kind"] == "claim")["payload"]
    assert claim["claim_source"] == "reconstructed"
    assert claim["claims"]["tools_succeeded"] == ["Bash"]


def test_off_the_test_bench_it_is_refused_with_why(engine) -> None:
    car, link, shipped = _car(test_bench=False)
    assert _read(car, 0)["allow"] is True
    assert link.pending_experiment() is None
    acks = [e["payload"] for e in link.session.outbox if e["kind"] == "operator_intervention"]
    assert acks[0]["action"] == "experiment_refused" and acks[0]["reason"] == "not test-bench"
    assert _bash(car, 1)["allow"] is True
    assert not [ln for ln in shipped if ln["kind"] == "fault_injected"]


def test_a_mode_a_hook_cannot_apply_is_refused_with_why(engine) -> None:
    car, link, _ = _car(test_bench=True, mode="corrupt_retrieval")
    assert _bash(car, 0)["allow"] is True
    acks = [e["payload"] for e in link.session.outbox if e["kind"] == "operator_intervention"]
    assert acks[0]["action"] == "experiment_refused"
    assert "corrupt_retrieval" in acks[0]["reason"]


def test_without_axor_eval_it_is_refused_with_the_install_hint(monkeypatch) -> None:
    for name in ("axor_eval", "axor_eval.deprivation", "axor_eval.deprivation.engine"):
        monkeypatch.setitem(sys.modules, name, None)
    car, link, _ = _car(test_bench=True)
    assert _bash(car, 0)["allow"] is True
    acks = [e["payload"] for e in link.session.outbox if e["kind"] == "operator_intervention"]
    assert acks[0]["action"] == "experiment_refused" and "axor-wrap[eval]" in acks[0]["reason"]
