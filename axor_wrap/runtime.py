"""The wrapped runtime — every tool call goes through the real kernel.

``WrappedToolset`` holds ``{name: callable}`` plus the tools' manifests, builds
an ``axor_core.governor.ToolCallGovernor`` from the compiled config, and gates
each call: ``evaluate → (deny → ToolDenied) → call → register_output``. With
``enforcement="off"`` the same path runs and records, but a deny does not block
— that is an UNGOVERNED arm, which is observed but not enforced, and is a
different thing from an unwrapped agent that nothing observed at all. That is
the exact usage contract the governor documents, and the same decision path the
Control Plane and axor-lab's real-kernel backend run.

axor-core is a REQUIRED dependency — this module's whole job is gating through
the real kernel, and a wrap that cannot gate is not a wrap. The import stays
lazy so a test can inject a governor and so the scanner path pays no import
cost, not because the kernel is optional. For frameworks that own their invocation loop (LangChain executors, MCP
servers), ``wrap_callables`` returns drop-in wrapped callables that share one
governor session.
"""

from __future__ import annotations

import functools
from typing import Callable

from axor_wrap.compile import compile_manifests, governor_kwargs

ENFORCEMENT_ON = "on"
ENFORCEMENT_OFF = "off"
from axor_wrap.errors import (
    AdmissionHeld,
    KernelNotInstalledError,
    ToolDenied,
    UnknownToolError,
)
from axor_wrap.trace import SessionRecorder


def _kernel_version() -> str | None:
    """The pinned identity of the kernel that produced these verdicts.

    Load-bearing on a trace: the same events under a different kernel can yield
    a different verdict, so a trace that does not name its kernel cannot be
    replayed against the build that decided it.
    """
    try:
        import axor_core
    except ImportError:  # pragma: no cover - axor-core is a hard dependency
        return None
    return f"axor-core@{getattr(axor_core, '__version__', 'unknown')}"


def _build_governor(kwargs: dict[str, object]) -> object:
    try:
        from axor_core.governor import ToolCallGovernor
    except ImportError as exc:
        raise KernelNotInstalledError() from exc
    return ToolCallGovernor(**kwargs)  # type: ignore[arg-type]


class WrappedToolset:
    """Governed execution of a set of tool callables.

    One instance per agent session: the governor it holds carries the per-value
    taint ledger across the session's calls, so do not share an instance between
    concurrent sessions.
    """

    def __init__(
        self,
        tools: dict[str, Callable[..., object]],
        manifests: list[dict[str, object]],
        *,
        policy: dict[str, object] | None = None,
        governor: object | None = None,
        admission: Callable[[], bool] | None = None,
        enforcement: str = ENFORCEMENT_ON,
        record: bool = False,
        inputs: dict[str, object] | None = None,
    ) -> None:
        """``governor`` overrides construction (tests / custom kernels); otherwise
        the governor is built lazily-imported from axor-core with the kwargs
        compiled from ``manifests`` (+ optional ``policy`` allowlist).

        ``admission`` is an optional zero-arg predicate polled at the intent
        boundary (before the governor runs) — ``False`` means an operator has
        paused/stopped this node, and the call is held with ``AdmissionHeld``.
        ``PlaneConnector.gate`` wires this to a live ``PlaneSession``, so a
        Control-Plane pause/stop actually halts real tool execution.

        ``enforcement`` is ``"on"`` (deny blocks the call) or ``"off"``
        (observe-only: the governor still evaluates every call and still
        registers every output, so the taint ledger and the verdicts are built
        exactly as under enforcement — nothing is blocked). Off is what an
        UNGOVERNED experiment arm needs, and it is not the same as skipping the
        governor: an unwrapped agent produces no ledger, no verdicts, and no way
        to turn governance on later without re-integrating. Switching an arm
        from ungoverned to governed is this flag and nothing else.

        ``record`` keeps each call's raw arguments and result in memory so
        :meth:`trace` can emit a ``trace/v1`` document. Off by default: the
        kernel deliberately does not retain raw values, and a long-lived
        production wrap should not either. An experiment trial turns it on,
        because a trial that cannot produce its trace produces nothing.

        ``inputs`` are the scenario's declared inputs, needed to expand a
        ``$inputs.x`` allowlist reference into concrete destinations. Without
        them such a policy governs against the reference STRING, which denies
        every real destination and allows the placeholder."""
        self._tools = dict(tools)
        self.manifests = list(manifests)
        self.policy = dict(policy) if policy else None
        self.inputs = dict(inputs) if inputs else None
        self.config = governor_kwargs(self.manifests, policy, inputs)
        self._governor = governor if governor is not None else _build_governor(self.config)
        self._admission = admission
        if enforcement not in (ENFORCEMENT_ON, ENFORCEMENT_OFF):
            raise ValueError(
                f"enforcement must be {ENFORCEMENT_ON!r} or {ENFORCEMENT_OFF!r}, "
                f"got {enforcement!r}"
            )
        self.enforcement = enforcement
        self._recorder = SessionRecorder() if record else None

    def runtime_config_hash(self, kernel: str) -> str:
        """The fingerprint of the config this session ACTUALLY governed under.

        Lab records it on the trial and recomputes it from the assignment it
        issued; a mismatch means the runtime governed a different contract than
        the one it was given, which is exactly what a bundle claiming "this is
        the config that produced this evidence" must not absorb silently.

        Byte-identical to axor-lab's ``runtime_config_hash`` — the same compiled
        form, with ``$inputs`` refs expanded, under the same canonicalizer.
        """
        from axor_wrap.trace import content_hash

        return content_hash({
            "kernel": kernel,
            **compile_manifests(self.manifests, self.policy, self.inputs),
        })

    @property
    def tool_names(self) -> tuple[str, ...]:
        return tuple(self._tools)

    @property
    def trace_events(self) -> list[object]:
        """The kernel's own TraceEvents for this session, in call order.

        Read straight off the governor — this wrapper keeps no parallel record.
        A second list maintained here would be a second instrumentation path,
        and the whole point is that there is one: the IntentLoop and the
        synchronous governor emit the SAME events, so one bridge serves both.
        """
        return list(self._governor.trace_events)  # type: ignore[attr-defined]

    def kernel_events(self, node_id: str | None = None) -> list[object]:
        """This session's trace in the shared kernel event schema.

        What a runtime pushes to Lab or to the Control Plane. Both consumers
        read this one feed; neither gets its own instrumentation.
        """
        from axor_wrap.plane.bridge import trace_to_kernel

        return list(trace_to_kernel(self.trace_events, node_id))  # type: ignore[arg-type]

    def set_admission(self, admission: Callable[[], bool] | None) -> None:
        """Install (or clear) the intent-boundary admission predicate. Used by
        ``PlaneConnector.gate`` to bind a live node's posture after the toolset
        is already constructed."""
        self._admission = admission

    def call(self, name: str, args: dict[str, object]) -> object:
        """Gate and execute one tool call.

        Holds the call with ``AdmissionHeld`` when a bound admission predicate
        reports the node paused/stopped; raises ``ToolDenied`` when the governor
        denies; otherwise runs the callable and registers its output back into
        the taint ledger.
        """
        if name not in self._tools:
            raise UnknownToolError(name, self.tool_names)
        if self._admission is not None and not self._admission():
            raise AdmissionHeld("paused-or-stopped")
        decision = self._governor.evaluate(name, args)  # type: ignore[attr-defined]
        # recorded at the moment the kernel is consulted, so the recorder stays
        # 1:1 and in order with the kernel's own events. A call refused before
        # this line (unknown tool, admission held) produced no verdict either.
        recorded = self._recorder.evaluated(name, args) if self._recorder else None
        if not decision.allowed and self.enforcement == ENFORCEMENT_ON:
            raise ToolDenied(decision.reason, decision.category)
        # observe-only: the verdict is recorded and reported, the call proceeds.
        # register_output still runs, so a denied-but-executed call's output
        # taints the ledger exactly as it would have — which is the whole point
        # of measuring what an UNGOVERNED agent actually does.
        output = self._tools[name](**args)
        self._governor.register_output(decision, output)  # type: ignore[attr-defined]
        if recorded is not None:
            recorded.executed, recorded.result = True, output
        return output

    def trace(
        self,
        trial: dict[str, object],
        *,
        scenario: dict[str, object] | None = None,
        trace_id: str | None = None,
        inputs_digest: str | None = None,
    ) -> dict[str, object]:
        """This session as a ``trace/v1`` document — what a runtime pushes to Lab.

        Pass the ``scenario`` this trial ran: a ``wrapped_code`` trace must
        carry an ``inputs_digest`` binding it to the world it ran in, and
        ``verify_bundle`` refuses one without it — so a trace built without the
        scenario is collected happily and then cannot be packaged.

        Requires ``record=True``: without it the raw arguments and results a
        trace's value ledger is built from were never kept, and a trace with an
        empty ledger cannot tie a sink argument back to an untrusted source,
        which is the one thing it exists to do.
        """
        from axor_wrap._version import get_version
        from axor_wrap.trace import build_trace

        if self._recorder is None:
            raise ValueError(
                "this toolset was built without record=True, so no values were kept; "
                "a trace built from it could carry verdicts but no provenance"
            )
        return build_trace(
            calls=self._recorder.calls,
            trace_events=self.trace_events,
            manifests=self.manifests,
            enforcement=self.enforcement,
            trial=trial,
            trace_id=trace_id,
            kernel_version=_kernel_version(),
            runtime=f"axor-wrap@{get_version('axor-wrap')}",
            scenario=scenario,
            inputs_digest=inputs_digest,
        )


def wrap_callables(
    tools: dict[str, Callable[..., object]],
    manifests: list[dict[str, object]],
    *,
    policy: dict[str, object] | None = None,
    governor: object | None = None,
    admission: Callable[[], bool] | None = None,
) -> dict[str, Callable[..., object]]:
    """Wrapped drop-in callables sharing ONE governor session.

    For frameworks that own their own invocation loop: hand these to LangChain /
    an MCP server instead of the raw functions; each call is gated exactly like
    ``WrappedToolset.call`` and raises ``ToolDenied`` on a kernel deny (or
    ``AdmissionHeld`` when a bound Control-Plane node is paused/stopped).
    """
    toolset = WrappedToolset(
        tools, manifests, policy=policy, governor=governor, admission=admission,
    )

    def _make(name: str, fn: Callable[..., object]) -> Callable[..., object]:
        @functools.wraps(fn)
        def wrapped(**kwargs: object) -> object:
            return toolset.call(name, kwargs)

        return wrapped

    return {name: _make(name, fn) for name, fn in tools.items()}
