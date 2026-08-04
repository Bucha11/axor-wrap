"""The streaming path writes its trace here too — same builder, no third path.

There are two ways to wrap an agent, decided by who owns the loop:

  - the framework owns it → ``WrappedToolset`` asks ``ToolCallGovernor``;
  - the kernel owns it → ``GovernedSession`` runs an ``IntentLoop``.

Only the first could produce a ``trace/v1``. So an agent wrapped the second way
— which is what the production integrations use — governed correctly and then
had nowhere to send the record: its verdicts sat in a ``TraceCollector`` that
nothing downstream reads. "Both paths write their traces to wrap" was half true.

What makes one builder possible is that axor-core now records the SAME verdicts
with the SAME provenance from one shared function on both paths. So this is not
a second trace builder; it is the same ``build_trace``, fed from the other side.

The one real difference is where the wrapper sits. On the streaming path the
kernel only hands over a tool it has already approved, so a DENIED call never
reaches the wrapper and has no recorded arguments. That is declared
(``observes=EXECUTIONS_ONLY``), not guessed from counts — guessing would
silently mis-pair a run whose numbers happened to line up, and a mis-paired
trace attributes one call's verdict to another call's arguments.
"""

from __future__ import annotations

from typing import Any

import pytest

from axor_wrap.trace import (
    EVERY_INTENT,
    EXECUTIONS_ONLY,
    SessionRecorder,
    TraceBuildError,
    record_tools,
    trace_of_session,
    trial_of,
    verdicts_of,
)

TAINTED = "PAY DE89370400440532013000"

# `read` / `write` are what the kernel's stock policy admits; the taxonomy below
# is what makes one a taint SOURCE and the other an egress SINK.
MANIFESTS = [
    {
        "schema_version": "tool-manifest/v1", "id": "read",
        "args_schema": {"type": "object", "properties": {}, "required": []},
        "result_schema": {"type": "object"},
        "effect": {"default_class": "READ", "driving_args": []},
        "untrusted_fields": ["result.description"],
        "side_effecting": False,
    },
    {
        "schema_version": "tool-manifest/v1", "id": "write",
        "args_schema": {"type": "object",
                        "properties": {"recipient": {"type": "string"}},
                        "required": ["recipient"]},
        "result_schema": {"type": "object"},
        "effect": {"default_class": "EXPORT", "driving_args": ["recipient"]},
        "side_effecting": True,
    },
]


def _envelope():
    """A minimal governed envelope admitting `read` and `write`.

    Built here rather than borrowed from axor-core's conftest: this test lives
    in axor-wrap, and a wrap test that needed the kernel's private test fixtures
    would be testing the fixtures.
    """
    from axor_core.capability.executor import CapabilityExecutor  # noqa: F401
    from axor_core.contracts.cancel import make_token
    from axor_core.contracts.context import ContextFragment, ContextView, LineageSummary
    from axor_core.contracts.envelope import Capabilities, ExecutionEnvelope, ExportContract
    from axor_core.contracts.policy import (
        ChildMode, CompressionMode, ContextMode, ExecutionPolicy, ExportMode,
        TaskComplexity, ToolPolicy,
    )

    lineage = LineageSummary(node_id="node_test_root", parent_id=None, depth=0,
                             ancestry_ids=[], inherited_restrictions=[])
    policy = ExecutionPolicy(
        name="wrap_test", derived_from=TaskComplexity.FOCUSED,
        context_mode=ContextMode.MINIMAL, compression_mode=CompressionMode.BALANCED,
        child_mode=ChildMode.DENIED, max_child_depth=0,
        tool_policy=ToolPolicy(allow_read=True, allow_write=True),
        export_mode=ExportMode.SUMMARY,
    )
    context = ContextView(
        node_id=lineage.node_id, working_summary="test task",
        visible_fragments=[ContextFragment(kind="fact", content="t",
                                           token_estimate=10, source="test")],
        active_constraints=[], lineage=lineage, token_count=10, compression_ratio=1.0,
    )
    return ExecutionEnvelope(
        node_id=lineage.node_id, task="test task", context=context, policy=policy,
        capabilities=Capabilities(
            allowed_tools=frozenset({"read", "write"}), allow_children=False,
            allow_nested_children=False, allow_context_expansion=False,
            allow_export=True, allow_mutation=True, max_child_depth=0,
        ),
        export_contract=ExportContract(
            mode=ExportMode.SUMMARY, allowed_fields=frozenset({"output"}),
            max_export_tokens=1024,
        ),
        lineage=lineage, cancel_token=make_token(),
    )


class _Session:
    """The surface `trace_of_session` reads: `all_traces()` -> objects with
    `.events`. Standing in for GovernedSession, which builds one per node."""

    def __init__(self, events: list) -> None:
        self._events = events

    def all_traces(self) -> list:
        trace = type("_Trace", (), {})()
        trace.events = self._events
        return [trace]


class _Handler:
    """A ToolHandler over a plain callable — the seam `record_tools` wraps."""

    def __init__(self, name: str, fn: Any) -> None:
        self._name, self._fn = name, fn

    @property
    def name(self) -> str:
        return self._name

    async def execute(self, args: dict[str, Any]) -> Any:
        return self._fn(**args)


async def _run_streaming(program: list[tuple[str, dict[str, Any]]]):
    """Drive a real IntentLoop over `program`, recording through wrap."""
    from axor_core.capability.executor import CapabilityExecutor
    from axor_core.contracts.result import ExecutorEvent, ExecutorEventKind
    from axor_core.node.intent_loop import IntentLoop

    executed: list[str] = []
    tools = {
        "read": lambda: {"description": TAINTED},
        "write": lambda recipient: (executed.append(recipient), {"ok": True})[1],
    }
    recorder = SessionRecorder(observes=EXECUTIONS_ONLY)
    recorded = record_tools(tools, recorder)

    cap = CapabilityExecutor()
    for name, fn in recorded.items():
        cap.register(_Handler(name, fn))

    async def _stream():
        for i, (tool, args) in enumerate(program):
            yield ExecutorEvent(
                kind=ExecutorEventKind.TOOL_USE,
                payload={"tool": tool, "args": args, "tool_use_id": f"t{i}"},
                node_id="node_test_root",
            )
        yield ExecutorEvent(
            kind=ExecutorEventKind.STOP,
            payload={"usage": {"input_tokens": 1, "output_tokens": 1, "tool_tokens": 0}},
            node_id="node_test_root",
        )

    events: list[Any] = []
    loop = IntentLoop(
        capability_executor=cap, trace_events=events,
        untrusted_sources={"read"}, egress_sinks={"write"},
        driving_args={"write": ["recipient"]},
    )
    return loop, events, recorder, executed, _stream


@pytest.mark.asyncio
class TestAStreamingRunProducesATrace:
    async def _trace(self, program):
        loop, events, recorder, executed, stream = await _run_streaming(program)
        async for _ in loop.run(stream(), _envelope()):
            pass

        trace = trace_of_session(
            _Session(events), recorder, trial_of("s:governed:0", run_id="r"),
            manifests=MANIFESTS,
        )
        return trace, executed

    async def test_the_attack_is_denied_and_recorded(
self) -> None:
        trace, executed = await self._trace([
            ("read", {}), ("write", {"recipient": TAINTED}),
        ])
        decisions = [e["decision"] for e in trace["events"]
                     if e["type"] == "gate_decision"]
        assert [d["verdict"] for d in decisions] == ["ALLOW", "DENY"]
        assert executed == [], "the denied call must not have run"

    async def test_the_denial_names_its_gate(
self) -> None:
        """The streaming path recorded a reason and no category, so a trace
        built from it had nothing to put in `decision.gate`."""
        trace, _ = await self._trace([
            ("read", {}), ("write", {"recipient": TAINTED}),
        ])
        denial = [e["decision"] for e in trace["events"]
                  if e["type"] == "gate_decision"][-1]
        assert denial["gate"] == "taint_floor"
        assert denial["reason"]

    async def test_the_executed_read_roots_its_untrusted_value(
self) -> None:
        trace, _ = await self._trace([
            ("read", {}), ("write", {"recipient": TAINTED}),
        ])
        results = [e for e in trace["events"] if e["type"] == "tool_result"]
        assert len(results) == 1, "only the approved call executed"
        produced = {str(v["value_id"]): v for v in trace["values"]}
        rooted = produced[results[0]["produces_value_ids"][0]]
        assert rooted["labels"] == ["untrusted_derived"]
        assert rooted["decision_value"] == TAINTED

    async def test_a_denied_call_binds_no_value_rather_than_inventing_one(
self) -> None:
        """The wrapper genuinely never saw those arguments — the kernel refused
        before the tool was handed over. Recording a fabricated value would put
        a hash in the ledger for content nothing ever observed."""
        trace, _ = await self._trace([
            ("read", {}), ("write", {"recipient": TAINTED}),
        ])
        intents = [e for e in trace["events"] if e["type"] == "tool_call_intent"]
        assert intents[1]["tool"] == "write"
        assert intents[1]["arg_bindings"] == {}
        denial = [e["decision"] for e in trace["events"]
                  if e["type"] == "gate_decision"][-1]
        assert denial["driving_value_id"] is None
        assert denial["driving_unresolved"]["arg"] == "recipient"

    async def test_a_clean_run_records_every_call(
self) -> None:
        trace, executed = await self._trace([
            ("write", {"recipient": "GB00CLEAN000000000000"}),
        ])
        decisions = [e["decision"] for e in trace["events"]
                     if e["type"] == "gate_decision"]
        assert [d["verdict"] for d in decisions] == ["ALLOW"]
        assert executed == ["GB00CLEAN000000000000"]

    async def test_it_validates_as_a_trace(
self) -> None:
        trace, _ = await self._trace([
            ("read", {}), ("write", {"recipient": TAINTED}),
        ])
        assert trace["schema_version"] == "trace/v1"
        assert trace["producer"]["mode"] == "wrapped_code"
        assert str(trace["producer"]["kernel_version"]).startswith("axor-core@")
        seqs = [e["seq"] for e in trace["events"]]
        assert seqs == list(range(len(seqs)))


class TestTheRecorderModeIsDeclared:
    def test_a_streaming_recorder_must_say_so(self) -> None:
        """Inferring the mode from counts would silently mis-pair a run whose
        numbers happened to match."""
        with pytest.raises(TraceBuildError) as excinfo:
            record_tools({}, SessionRecorder(observes=EVERY_INTENT))
        assert "already approved" in str(excinfo.value)

    def test_an_unknown_mode_is_refused(self) -> None:
        with pytest.raises(ValueError):
            SessionRecorder(observes="whenever")

    def test_a_tool_that_ran_outside_the_kernel_is_refused(self) -> None:
        """A record with no verdict means something executed ungoverned; a trace
        claiming to describe a governed run must not absorb it."""
        from axor_wrap.trace import build_trace

        recorder = SessionRecorder(observes=EXECUTIONS_ONLY)
        recorder.evaluated("write", {"recipient": "x"})
        with pytest.raises(TraceBuildError) as excinfo:
            build_trace(
                calls=recorder.calls, trace_events=[], manifests=MANIFESTS,
                enforcement="on", trial=trial_of("s:a:0", run_id="r"),
                observes=EXECUTIONS_ONLY,
            )
        assert "outside the kernel" in str(excinfo.value)


@pytest.mark.asyncio
class TestVerdictsAreFilteredFromEverythingElse:
    async def test_only_tool_call_verdicts_are_taken(
self) -> None:
        """A session's traces carry token accounting, spawns and degradation
        signals too; a trace's decisions are the tool-call verdicts."""
        loop, events, recorder, _, stream = await _run_streaming([("read", {})])
        async for _ in loop.run(stream(), _envelope()):
            pass

        session = _Session(events)
        assert len(events) > len(verdicts_of(session)), \
            "the session recorded more than verdicts, as expected"
        assert len(verdicts_of(session)) == 1
