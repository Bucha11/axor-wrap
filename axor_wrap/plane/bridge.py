"""Trace bridge — one trace, two consumers (spec 12.0 point 4).

The plane subscribes to the SAME event feed Eval records; there is no second
instrumentation path. This module translates axor-core :class:`TraceEvent`s
into kernel-schema :class:`~axor_core.kernel.events.Event`s so the runtime's
recorded trace flows straight to the plane service (telemetry) and the replay
fold — no per-consumer schema.

The mapping is deliberately lossy in one direction only: a kernel Event keeps
the governance-load-bearing columns (kind, gate/category, verdict, causal_root,
severity for facts) and drops adapter-cosmetic detail (token counts, cache
stats, routing) into ``payload`` untouched. Anything the fold or the UI reasons
over is a first-class column; everything else rides along.
"""
from __future__ import annotations

from dataclasses import asdict

from axor_core.contracts.trace import (
    CancelledEvent,
    ChildSpawnedEvent,
    ChildStaleEvent,
    DegradationTransitionEvent,
    IntentDeniedEvent,
    SourceQuarantinedEvent,
    SuspiciousIntentEvent,
    TaintPropagatedEvent,
    TraceEvent,
    TraceEventKind,
)
from axor_core.kernel.events import Event, EventKind, Verdict

# axor-core DegradationLevel name -> kernel Fact severity (== the recompute's
# level index). Denials become facts that drive level = max(severity(uncovered)).
_LEVEL_SEVERITY = {
    "NORMAL": 0, "CAUTIOUS": 1, "RESTRICTED": 2, "LOCKED": 3, "TERMINAL": 4,
}


def _level_name(level: object) -> str:
    """DegradationLevel enum or str -> canonical NORMAL..TERMINAL name."""
    name = getattr(level, "name", None)
    return name if name is not None else str(level or "NORMAL")


def _ts(index: int) -> str:
    # Trace ordering is by seq; ts is informational. The kernel is clock-free,
    # so a synthetic monotone stamp keeps replay bit-reproducible.
    return f"seq:{index}"


def trace_event_to_kernel(event: TraceEvent, node_id: str | None = None) -> Event | None:
    """Translate one TraceEvent. Returns None for events with no governance
    meaning on the plane (they stay in the full local trace)."""
    nid = node_id or event.node_id
    seq = event.sequence

    if isinstance(event, IntentDeniedEvent):
        category = str(event.payload.get("category") or "") or _category_of(event.reason)
        gate = _gate_of(category)
        if event.intent_kind == "tool_call":
            # A refused tool call is a TOOL_CALL with verdict DENY — that is what
            # the event schema says ("`verdict` … is the recorded overall gate
            # verdict for this call; `gate` is the denying gate's category if
            # denied"), what `replay` re-gates, and the only form a consumer can
            # replay. Mapping it to EventKind.DENIAL instead threw away the whole
            # payload the kernel had just recorded — the tool, the arguments, the
            # per-argument provenance, the driving root — and rebuilt it as
            # {reason, intent_kind}. The replay fold has no DENIAL branch, so the
            # call vanished from the fold entirely; the Control Plane's converter
            # has no trace/v1 representation for the kind and refused the run.
            return Event(
                seq=seq, node_id=nid, kind=EventKind.TOOL_CALL, ts=_ts(seq),
                gate=gate, verdict=Verdict.DENY,
                payload={**event.payload, "reason": event.reason},
            )
        # Everything else the kernel refuses (a spawn, a message) is not a tool
        # call and must not be dressed as one — DENIAL keeps it honest.
        return Event(
            seq=seq, node_id=nid, kind=EventKind.DENIAL, ts=_ts(seq),
            gate=gate, verdict=Verdict.DENY,
            payload={**event.payload, "reason": event.reason,
                     "category": category, "intent_kind": event.intent_kind},
        )
    if isinstance(event, DegradationTransitionEvent):
        d = asdict(event)
        new_level = _level_name(d.get("new_level"))
        # A transition upward is a fact for the recompute; keyed on the trigger.
        return Event(
            seq=seq, node_id=nid, kind=EventKind.FACT, ts=_ts(seq),
            causal_root=d.get("trigger_source_id"),
            payload={
                "fact_id": f"deg_{seq}",
                "fact_type": "degradation_transition",
                "severity": _LEVEL_SEVERITY.get(new_level, 0),
                "reason": d.get("reason", ""),
                "new_level": new_level,
                "previous_level": _level_name(d.get("previous_level")),
            },
        )
    if isinstance(event, SourceQuarantinedEvent):
        d = asdict(event)
        return Event(
            seq=seq, node_id=nid, kind=EventKind.FACT, ts=_ts(seq),
            causal_root=d.get("source_id"),
            payload={
                "fact_id": f"quar_{seq}",
                "fact_type": "source_quarantined",
                "severity": _LEVEL_SEVERITY["RESTRICTED"],
                "reason": d.get("reason", ""),
            },
        )
    if isinstance(event, TaintPropagatedEvent):
        # The run's SOURCE event. This branch existed and was unreachable: nothing
        # in axor-core ever constructed a TaintPropagatedEvent, so every bridged
        # trace arrived with verdicts and no origin — nothing for the fold to put
        # in `tainted_refs`, and the Control Plane refusing the run outright ("no
        # untrusted source in the recorded run (no tool_result)").
        #
        # `causal_root` is the value ref this event is about. It read `source_id`,
        # a field this event class does not have, so it was always None.
        return Event(
            seq=seq, node_id=nid, kind=EventKind.TOOL_RESULT, ts=_ts(seq),
            causal_root=event.payload.get("value_ref"),
            payload=dict(event.payload),
        )
    if isinstance(event, SuspiciousIntentEvent):
        denied = event.policy_action == "denied"
        return Event(
            seq=seq, node_id=nid,
            kind=EventKind.DENIAL if denied else EventKind.GATE_EVAL, ts=_ts(seq),
            gate="anomaly", verdict=Verdict.DENY if denied else Verdict.PASS,
            payload={"tool": event.tool, "score": event.score,
                     "reasons": list(event.reasons)},
        )
    if isinstance(event, ChildSpawnedEvent) or event.kind is TraceEventKind.CHILD_SPAWNED:
        # Tree shape derives from traced spawn events, never from a node
        # self-reporting its parent (spec v2 Ch.4 §6).
        d = asdict(event)
        return Event(
            seq=seq, node_id=nid, kind=EventKind.NODE_SPAWNED, ts=_ts(seq),
            payload={
                "child_id": d.get("child_node_id")
                or event.payload.get("child_node_id", ""),
                "parent_id": nid,
                "depth": d.get("child_depth", event.payload.get("child_depth", 0)),
                "edge_kind": "delegation",
            },
        )
    if isinstance(event, ChildStaleEvent) or event.kind is TraceEventKind.CHILD_STALE:
        d = asdict(event)
        child = d.get("child_node_id") or event.payload.get("child_node_id", "")
        return Event(
            seq=seq, node_id=nid, kind=EventKind.FACT, ts=_ts(seq),
            payload={
                "fact_id": f"stale_{seq}",
                "fact_type": "node_stale",
                "severity": _LEVEL_SEVERITY["CAUTIOUS"],
                "reason": event.payload.get("error", "child died without returning"),
                "child_id": child,
            },
        )
    if event.kind is TraceEventKind.CHILD_COMPLETED:
        # Normal death: the result returns up the spawn edge (message-as-source
        # at the parent, spec v2 Ch.4 §4). Carried labels ride in the payload
        # when the recorder provided them.
        return Event(
            seq=seq, node_id=nid, kind=EventKind.MESSAGE_RECEIVED, ts=_ts(seq),
            causal_root=event.payload.get("value_ref"),
            payload={
                "from": event.payload.get("child_node_id", ""),
                "edge_kind": "delegation",
                "msg_id": f"ret_{seq}",
                "value_ref": event.payload.get("value_ref"),
                "carried": event.payload.get("carried", {}),
            },
        )
    if isinstance(event, CancelledEvent):
        return Event(
            seq=seq, node_id=nid, kind=EventKind.OPERATOR_INTERVENTION, ts=_ts(seq),
            payload={"reason": event.reason, "detail": event.detail},
        ) if "control plane" in event.detail else None

    # An approved call — and a TRANSFORMED one, which is also an executed call
    # (with rewritten arguments) and was silently dropped here: the run's most
    # interesting allow, the one the kernel changed, left no TOOL_CALL for the
    # fold to re-gate.
    if event.kind in (
        TraceEventKind.INTENT_APPROVED, TraceEventKind.INTENT_TRANSFORMED,
    ):
        return Event(
            seq=seq, node_id=nid, kind=EventKind.TOOL_CALL, ts=_ts(seq),
            verdict=Verdict.PASS, payload=dict(event.payload),
        )
    # Cosmetic adapter events (tokens/cache/routing) carry no governance meaning
    # and stay in the local trace only.
    return None


def _gate_of(category: str) -> str:
    """The gate name a denial category maps to, from axor-core's own table.

    The kernel exports ``GATE_OF_CATEGORY`` precisely so consumers stop keeping
    private copies; a category it does not know is passed through rather than
    raising, because a bridge that drops an event on an unrecognised label
    silently loses a denial — the one thing a governance trace must never do.
    """
    from axor_core.governor import GATE_OF_CATEGORY

    return GATE_OF_CATEGORY.get(category, category or "denial")


def _category_of(reason: str) -> str:
    """LAST-RESORT category for a denial that carries none.

    Guessing a gate from substrings of a human-readable reason string is not a
    mapping, it is a coincidence: reword a reason and the gate silently changes.
    Every denial axor-core records now carries ``payload["category"]``, the
    kernel's own label, and that is what the bridge reads. This stays only for a
    trace recorded by an older build — and it returns the category, which
    :func:`_gate_of` then maps, so there is one gate table, not two.
    """
    lowered = reason.lower()
    for needle, cat in (
        ("taint", "taint_enforcement"), ("carrier", "carrier_gate"),
        ("consequence", "consequence_gate"), ("ssrf", "ssrf_gate"),
        ("value policy", "value_policy"), ("capability", "capability"),
        ("budget", "budget"), ("degradation", "degradation"),
        ("unclassified", "unclassified_tool"), ("positional", "positional_gate"),
    ):
        if needle in lowered:
            return cat
    return "denial"


def trace_to_kernel(events: list[TraceEvent], node_id: str | None = None) -> list[Event]:
    """Translate a full trace, dropping non-governance events."""
    out = []
    for event in events:
        kernel = trace_event_to_kernel(event, node_id)
        if kernel is not None:
            out.append(kernel)
    return out
