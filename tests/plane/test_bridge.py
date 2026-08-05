"""Trace bridge: axor-core TraceEvents -> kernel Events -> replay fold.

One trace, two consumers (spec 12.0 point 4): a refused tool call becomes a
TOOL_CALL with verdict DENY (which is what the event schema says and what the
replay fold re-gates), degradation transitions become facts that drive the
recompute, and the translated stream folds through the kernel replay that the
platform's scrubber/regression use.

It did not. A tool-call denial was mapped to EventKind.DENIAL with the payload
REBUILT as {reason, intent_kind} — discarding the tool, the arguments and the
provenance the kernel had just recorded — and the gate GUESSED by substring of
the reason text. The replay fold has no DENIAL branch, so those calls vanished
from the fold; the Control Plane's converter has no trace/v1 representation for
the kind and refused whole runs. The gate now comes from the kernel's own
recorded category via `axor_core.governor.GATE_OF_CATEGORY`.
"""
from __future__ import annotations

from axor_core.contracts.degradation import DegradationLevel
from axor_core.contracts.trace import (
    DegradationTransitionEvent,
    IntentDeniedEvent,
    TokensSpentEvent,
    TraceEventKind,
)
from axor_core.kernel.events import EventKind, Verdict
from axor_core.kernel.replay import replay
from axor_wrap.plane.bridge import trace_event_to_kernel, trace_to_kernel


def test_a_refused_tool_call_is_a_tool_call_with_a_deny_verdict() -> None:
    """Not EventKind.DENIAL: the fold's TOOL_CALL branch is the only one that
    re-gates a call, so a denial recorded as DENIAL is a call replay never
    sees."""
    ev = IntentDeniedEvent(
        kind=TraceEventKind.INTENT_DENIED, node_id="n0", sequence=3,
        intent_kind="tool_call",
        reason="taint enforcement (per-value): tainted value into export",
        payload={"tool": "send", "args": {"to": "x"}, "category": "taint_enforcement",
                 "driving_root": {"sources": ["web"], "sensitive": False}},
    )
    kernel = trace_event_to_kernel(ev)
    assert kernel is not None
    assert kernel.kind is EventKind.TOOL_CALL
    assert kernel.verdict is Verdict.DENY
    # the GATE name, from axor-core's table — not the category, and not a guess
    assert kernel.gate == "taint_floor"


def test_the_denied_call_keeps_the_provenance_the_kernel_recorded() -> None:
    """The payload was rebuilt as {reason, intent_kind}. Everything the kernel
    computed to REACH the verdict — the tool, the arguments, the driving root —
    was dropped on the floor, so no consumer could say what was denied on."""
    ev = IntentDeniedEvent(
        kind=TraceEventKind.INTENT_DENIED, node_id="n0", sequence=1,
        intent_kind="tool_call", reason="taint enforcement",
        payload={"tool": "send", "args": {"to": "attacker"},
                 "arg_refs": {"to": "v1"}, "category": "taint_enforcement",
                 "driving_args": ["to"],
                 "driving_root": {"sources": ["web"], "sensitive": False}},
    )
    kernel = trace_event_to_kernel(ev)
    assert kernel is not None
    assert kernel.payload["tool"] == "send"
    assert kernel.payload["args"] == {"to": "attacker"}
    assert kernel.payload["arg_refs"] == {"to": "v1"}
    assert kernel.payload["driving_root"]["sources"] == ["web"]
    assert kernel.payload["reason"] == "taint enforcement"


def test_a_refused_spawn_stays_a_denial() -> None:
    """A non-tool-call refusal must not be dressed up as a tool call — replay
    would re-gate a call that never existed."""
    ev = IntentDeniedEvent(
        kind=TraceEventKind.INTENT_DENIED, node_id="n0", sequence=2,
        intent_kind="spawn_child", reason="carrier gate: imperative channel",
        payload={"category": "carrier_gate"},
    )
    kernel = trace_event_to_kernel(ev)
    assert kernel is not None
    assert kernel.kind is EventKind.DENIAL
    assert kernel.gate == "carrier"
    assert kernel.payload["intent_kind"] == "spawn_child"


def test_the_recorded_category_wins_over_the_reason_text() -> None:
    """Guessing a gate from substrings of a human-readable reason is not a
    mapping, it is a coincidence: this reason mentions no gate at all, and the
    old code would have written `denial`."""
    ev = IntentDeniedEvent(
        kind=TraceEventKind.INTENT_DENIED, node_id="n0", sequence=0,
        intent_kind="tool_call", reason="refused",
        payload={"category": "consequence_gate"},
    )
    kernel = trace_event_to_kernel(ev)
    assert kernel is not None
    assert kernel.gate == "consequence"


def test_a_taint_propagated_event_becomes_the_runs_source() -> None:
    """This branch was unreachable — nothing in axor-core constructed the event
    — so a bridged trace had verdicts and no origin. The fold registers
    `value_ref` from here; without it every `arg_refs` binding resolves to
    nothing and the Control Plane refuses the run for having no source."""
    from axor_core.contracts.trace import TaintPropagatedEvent

    ev = TaintPropagatedEvent(
        kind=TraceEventKind.TAINT_PROPAGATED, node_id="n0", sequence=0,
        taint_source="web", taint_scope="value",
        payload={"tool": "read", "status": "ok", "value_ref": "v1",
                 "root": {"sources": ["web"], "sensitive": False}},
    )
    kernel = trace_event_to_kernel(ev)
    assert kernel is not None
    assert kernel.kind is EventKind.TOOL_RESULT
    assert kernel.causal_root == "v1"
    assert kernel.payload["root"]["sources"] == ["web"]


def test_degradation_transition_becomes_a_fact_severity() -> None:
    ev = DegradationTransitionEvent(
        kind=TraceEventKind.DEGRADATION_TRANSITION, node_id="n0", sequence=5,
        previous_level=DegradationLevel.NORMAL, new_level=DegradationLevel.RESTRICTED,
        trigger_source_id="src_1", trigger_intent="bash", reason="tainted exec",
    )
    kernel = trace_event_to_kernel(ev)
    assert kernel is not None
    assert kernel.kind is EventKind.FACT
    assert kernel.payload["severity"] == int(DegradationLevel.RESTRICTED)
    assert kernel.causal_root == "src_1"


def test_cosmetic_events_are_dropped() -> None:
    ev = TokensSpentEvent(
        kind=TraceEventKind.TOKENS_SPENT, node_id="n0", sequence=1,
        input_tokens=10, output_tokens=5,
    )
    assert trace_event_to_kernel(ev) is None


def test_translated_trace_folds_and_recomputes_level() -> None:
    trace = [
        IntentDeniedEvent(
            kind=TraceEventKind.INTENT_DENIED, node_id="n0", sequence=0,
            intent_kind="tool_call", reason="carrier gate: imperative channel",
        ),
        DegradationTransitionEvent(
            kind=TraceEventKind.DEGRADATION_TRANSITION, node_id="n0", sequence=1,
            previous_level=DegradationLevel.NORMAL,
            new_level=DegradationLevel.RESTRICTED,
            trigger_source_id="src_1", trigger_intent="bash", reason="tainted",
        ),
    ]
    events = trace_to_kernel(trace)
    assert len(events) == 2
    result = replay(events)  # scrubber-mode fold
    # the degradation fact drives the recompute to RESTRICTED
    assert result.steps[-1].state.level is DegradationLevel.RESTRICTED
