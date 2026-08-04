"""Turning a wrapped session into a ``trace/v1`` document.

This is the missing half of "bring your own agent". A wrapped runtime could
already gate through the real kernel and hand its verdicts to the Control Plane
(``plane.bridge.trace_to_kernel``), but it could not produce the trace axor-lab
consumes — so a runtime executing a Lab assignment had to reach back into Lab
for a gate and a loop, which is a third gating path nobody wants.

**Who supplies what.** The kernel supplies the VERDICTS and the PROVENANCE: it
already computes, per call, which arguments carry taint, what the driving root
joins to, and whether the confidentiality floor is armed, and it records all of
it on its own trace events. This module never re-derives any of that. What the
kernel deliberately does not record is the raw VALUES — arguments and tool
results — and those are exactly what the wrapper has in hand as it executes. So
the trace is a join: values from the wrapper, verdicts and lineage from the
kernel. Neither side keeps a second copy of the other's.

**A note on the provenance model.** ``provenance_fidelity`` is
``explicit_flow_tracked`` because the kernel's per-value engine is the real
thing — content-derivation over a closed constructor set, not a heuristic. It
is worth being precise that this is NOT the same rule as a simulator's
conservative join, which taints every model-emitted value while any untrusted
value is live in context. That rule over-taints on purpose; content-derivation
tracks actual derivation. The trace must record what the kernel SAW, because the
kernel is what decided: labelling a value untrusted where the kernel found it
clean would produce a trace whose replay contradicts its own recorded verdict.

**Hashes.** ``canonical_value_hash`` uses ``axor_core.kernel.canonicalize`` —
the same RFC 8785 canonicalizer Lab hashes with, byte-identical on the
float-free subset a trace occupies. Reimplementing it here is how two sides of
one hash quietly stop agreeing.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from axor_wrap.errors import AxorWrapError

SCHEMA_VERSION = "trace/v1"
NODE_ROOT = "root"

LABEL_UNTRUSTED = "untrusted_derived"
LABEL_PROMPT_GIVEN = "prompt_given"
LABEL_SENSITIVE = "sensitive"

REDACTED_PREVIEW = "[redacted]"
_PREVIEW_MAX = 120

# What an ALLOW names. No gate denied, but `decision.gate` is required, and the
# taint floor is the last gate in the sequence a call clears — so an allow says
# "cleared through the floor". This matches what axor-lab's own real-kernel
# backend records, and parity matters more here than a prettier field: the two
# producers' traces have to be comparable.
GATE_ON_ALLOW = "taint_floor"
PROJECTION_UNTRUSTED = "untrusted-derived"


class TraceBuildError(AxorWrapError):
    """The session and the kernel's record disagree, so no trace can be built."""


@dataclass
class RecordedCall:
    """One gated call, as the wrapper saw it.

    Recorded at the moment the kernel is consulted, so this list stays 1:1 and
    in order with the kernel's own trace events. A call rejected before the
    kernel runs (unknown tool, admission held) produces no entry, because the
    kernel produced no verdict for it either.
    """

    tool: str
    args: dict[str, Any]
    executed: bool = False
    result: Any = None


@dataclass
class SessionRecorder:
    """The raw values a trace needs. Verdicts come from the kernel, not here."""

    calls: list[RecordedCall] = field(default_factory=list)

    def evaluated(self, tool: str, args: dict[str, Any]) -> RecordedCall:
        call = RecordedCall(tool=tool, args=dict(args))
        self.calls.append(call)
        return call

    def clear(self) -> None:
        self.calls.clear()


# ── canonical hashing ────────────────────────────────────────────────────────


def content_hash(value: object) -> str:
    """``sha256:<hex>`` over the kernel's canonical serialization."""
    from axor_core.kernel import canonicalize

    return f"sha256:{hashlib.sha256(canonicalize(value)).hexdigest()}"


def _preview(value: object) -> str:
    text = value if isinstance(value, str) else repr(value)
    return text[:_PREVIEW_MAX]


# ── the value ledger ─────────────────────────────────────────────────────────


class _Ledger:
    def __init__(self) -> None:
        self.values: list[dict[str, Any]] = []
        self._counter = 0
        self.untrusted_ids: list[str] = []

    def _mint(
        self, value: object, *, hint: str, labels: list[str],
        sources: list[dict[str, str]], sensitive: bool,
        transformations: list[str] | None = None,
        derived_from: list[str] | None = None,
    ) -> str:
        self._counter += 1
        value_id = f"v_{hint}_{self._counter}"
        entry: dict[str, Any] = {
            "value_id": value_id,
            "canonical_value_hash": content_hash(value),
            "labels": labels,
            "sources": sources,
        }
        if sensitive:
            # a sensitive value never carries its content into the trace: the
            # hash still binds it, but a policy that turns on the value cannot
            # be replayed exactly. The schema documents that tradeoff.
            entry["preview"] = REDACTED_PREVIEW
        else:
            entry["preview"] = _preview(value)
            entry["decision_value"] = value
        if transformations:
            entry["transformations"] = transformations
        if derived_from:
            entry["derived_from"] = derived_from
        self.values.append(entry)
        if LABEL_UNTRUSTED in labels:
            self.untrusted_ids.append(value_id)
        return value_id

    def mint_argument(self, tool: str, name: str, value: object,
                      ref: dict[str, Any]) -> str:
        """An argument the agent chose, labelled from the kernel's own reading.

        `ref` is the kernel's `arg_refs[name]`: the taint sources it derived for
        this argument and whether it is sensitive. An empty source set means the
        kernel found no derivation — recording it as untrusted anyway would put
        a label in the trace that contradicts the verdict recorded beside it.
        """
        taint_sources = [str(s) for s in ref.get("sources", [])]
        sensitive = bool(ref.get("sensitive"))
        if not taint_sources:
            return self._mint(
                value, hint="const", labels=[LABEL_PROMPT_GIVEN],
                sources=[{"kind": "constant", "origin_ref": f"arg:{tool}:{name}"}],
                sensitive=sensitive,
            )
        labels = [LABEL_UNTRUSTED] + ([LABEL_SENSITIVE] if sensitive else [])
        return self._mint(
            value, hint="model", labels=labels,
            sources=[{"kind": "external_read", "origin_ref": f"taint:{s}"}
                     for s in taint_sources],
            sensitive=sensitive,
            # the agent produced this value from its context; `derived_from` is
            # the immediate edge, and the untrusted values live at the call are
            # the sound over-approximation of it (the schema permits a superset,
            # never an omission).
            transformations=["model_extraction"],
            derived_from=list(self.untrusted_ids),
        )

    def mint_read(self, tool: str, path: str, value: object, sensitive: bool) -> str:
        return self._mint(
            value, hint="ext",
            labels=[LABEL_UNTRUSTED] + ([LABEL_SENSITIVE] if sensitive else []),
            sources=[{"kind": "external_read",
                      "origin_ref": f"tool_result:{tool}:{path}"}],
            sensitive=sensitive,
        )


# ── untrusted-field extraction ───────────────────────────────────────────────


def _strip_result(path: str) -> str:
    return path[len("result."):] if path.startswith("result.") else path


def _normalize(path: str) -> str:
    import re

    return re.sub(r"\[\d*\]", "[]", _strip_result(path))


def _expand(node: object, path: str) -> list[tuple[str, object]]:
    """Expand `transactions[].description` into the concrete (path, value) pairs
    actually present. Values stay typed, so the ledger stores the exact value
    the kernel evaluated rather than a stringification of it."""
    if not path:
        return [("", node)] if isinstance(node, (str, int, float, bool)) else []
    head, _, rest = path.partition(".")
    if head.endswith("[]"):
        key = head[:-2]
        items = node.get(key, []) if isinstance(node, dict) else []
        out: list[tuple[str, object]] = []
        for i, item in enumerate(items if isinstance(items, list) else []):
            for sub, value in _expand(item, rest):
                out.append((f"{key}[{i}]{'.' + sub if sub else ''}", value))
        return out
    if not isinstance(node, dict) or head not in node:
        return []
    for sub, value in _expand(node[head], rest):
        return [(f"{head}.{sub}" if sub else head, value)]
    return []


def _mint_untrusted_fields(
    ledger: _Ledger, manifest: dict[str, Any], tool: str, result: object
) -> list[str]:
    sensitive_patterns = {_normalize(str(p)) for p in manifest.get("sensitive_fields", [])}
    produced: list[str] = []
    for pattern in manifest.get("untrusted_fields", []):
        is_sensitive = _normalize(str(pattern)) in sensitive_patterns
        for path, value in _expand(result, _strip_result(str(pattern))):
            produced.append(ledger.mint_read(tool, path, value, is_sensitive))
    return produced


# ── the build ────────────────────────────────────────────────────────────────


def _decision_of(event: Any, arg_bindings: dict[str, str], enforced: bool) -> dict[str, Any]:
    from axor_core.governor import gate_of

    payload: dict[str, Any] = dict(getattr(event, "payload", {}) or {})
    denied = str(getattr(event.kind, "value", event.kind)) == "intent_denied"
    driving = [str(a) for a in payload.get("driving_args", [])]
    driving_value_id = arg_bindings.get(driving[0]) if driving else None

    decision: dict[str, Any] = {
        "verdict": "DENY" if denied else "ALLOW",
        "gate": gate_of(str(payload["category"])) if denied else GATE_ON_ALLOW,
        "driving_value_id": driving_value_id,
        "enforced": enforced,
    }
    reason = getattr(event, "reason", None)
    if reason:
        decision["reason"] = str(reason)
    if denied:
        decision["projection"] = PROJECTION_UNTRUSTED
    if driving_value_id is None:
        # never invent a value id for a call with no resolvable driving value —
        # the typed reason is what a fail-closed decision carries instead.
        decision["driving_unresolved"] = (
            {"kind": "no_driving_args"} if not driving
            else {"kind": "unresolved_argument", "arg": driving[0]}
        )
    return decision


def build_trace(
    *,
    calls: list[RecordedCall],
    trace_events: list[Any],
    manifests: list[dict[str, Any]],
    enforcement: str,
    trial: dict[str, Any],
    trace_id: str | None = None,
    kernel_version: str | None = None,
    runtime: str | None = None,
    inputs_digest: str | None = None,
) -> dict[str, Any]:
    """A ``trace/v1`` document for one trial.

    ``calls`` and ``trace_events`` must line up one-to-one and in order: one
    kernel verdict per gated call. They are built by the same code path, so a
    mismatch means the session was mutated underneath the recorder — raised
    rather than papered over, because a misaligned trace attributes one call's
    verdict to another call's arguments, which is worse than no trace at all.
    """
    if len(calls) != len(trace_events):
        raise TraceBuildError(
            f"{len(calls)} recorded call(s) but {len(trace_events)} kernel verdict(s) — "
            "refusing to emit a trace that would pair a verdict with the wrong call"
        )
    by_id = {str(m.get("id")): m for m in manifests}
    ledger = _Ledger()
    events: list[dict[str, Any]] = []
    enforced = enforcement != "off"
    seq = 0

    for index, (call, event) in enumerate(zip(calls, trace_events)):
        refs: dict[str, Any] = dict((getattr(event, "payload", {}) or {}).get("arg_refs", {}))
        arg_bindings = {
            name: ledger.mint_argument(call.tool, name, value, refs.get(name, {}))
            for name, value in call.args.items()
        }
        call_id = f"call_{NODE_ROOT}_{index}"
        events.append({"seq": seq, "node": NODE_ROOT, "type": "tool_call_intent",
                       "tool": call.tool, "call_id": call_id,
                       "arg_bindings": arg_bindings})
        seq += 1
        events.append({"seq": seq, "node": NODE_ROOT, "type": "gate_decision",
                       "call_id": call_id,
                       "decision": _decision_of(event, arg_bindings, enforced)})
        seq += 1
        if call.executed:
            produced = _mint_untrusted_fields(
                ledger, by_id.get(call.tool, {}), call.tool, call.result,
            )
            events.append({"seq": seq, "node": NODE_ROOT, "type": "tool_result",
                           "tool": call.tool, "produces_value_ids": produced})
            seq += 1

    producer: dict[str, Any] = {
        "mode": "wrapped_code",
        "provenance_fidelity": "explicit_flow_tracked",
    }
    if kernel_version:
        producer["kernel_version"] = kernel_version
    if runtime:
        producer["runtime"] = runtime

    trace: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "trace_id": trace_id or _default_trace_id(trial),
        "trial": dict(trial),
        "producer": producer,
        "events": events,
        "values": ledger.values,
    }
    if inputs_digest:
        trace["inputs_digest"] = inputs_digest
    return trace


def _default_trace_id(trial: dict[str, Any]) -> str:
    return (
        f"t_{trial.get('run_id')}_{trial.get('scenario_id')}_"
        f"{trial.get('condition_id')}_{trial.get('seed')}_r{trial.get('repeat_index')}"
    )


def trial_of(trial_unit: str, run_id: str, seed: str | None = None) -> dict[str, Any]:
    """The `trial` block for a planned unit ``scenario:arm:repeat``.

    The full coordinate, deliberately: a trace identified by less than
    (run, scenario, condition, seed, repeat) collides with its siblings, and
    colliding traces overwrite each other in a bundle.
    """
    try:
        scenario_id, condition_id, index = str(trial_unit).rsplit(":", 2)
        repeat_index = int(index)
    except ValueError as exc:
        raise TraceBuildError(f"malformed trial unit {trial_unit!r}") from exc
    return {
        "run_id": run_id,
        "scenario_id": scenario_id,
        "condition_id": condition_id,
        "seed": seed if seed is not None else f"s{repeat_index:03d}",
        "repeat_index": repeat_index,
    }
