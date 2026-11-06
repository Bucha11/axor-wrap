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
    KernelIncompatibleError,
    KernelNotInstalledError,
    ToolDenied,
    UnknownToolError,
)
from axor_wrap.trace import SessionRecorder


def _require_contract_kernel() -> None:
    """Consumption contracts need a kernel that implements them AND returns the
    prepared arguments it judged. Checked at construction, so an incompatible
    install fails before any call rather than by quietly running raw proposals."""
    try:
        import inspect

        from axor_core.governor import GovernanceDecision, ToolCallGovernor
        import axor_core.kernel.consumption  # noqa: F401
    except ImportError as exc:
        raise KernelIncompatibleError(
            "consumption contracts need an axor-core that provides "
            "axor_core.kernel.consumption (the release that adds field_contracts)"
        ) from exc
    params = inspect.signature(ToolCallGovernor.__init__).parameters
    fields = getattr(GovernanceDecision, "__dataclass_fields__", {})
    if "field_contracts" not in params or "args" not in fields:
        raise KernelIncompatibleError(
            "the installed axor-core does not accept field_contracts or does not "
            "return GovernanceDecision.args — upgrade axor-core"
        )


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
        node_id: str = "",
        field_contracts: dict[str, object] | None = None,
        consumption_attested: "set[str] | frozenset[str] | None" = None,
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
        every real destination and allows the placeholder.

        ``node_id`` stamps the kernel's own trace events. Left empty the
        governor emits events with no node, which is fine for a single-session
        trace built by :meth:`trace` (the document names its own trial) but not
        for a caller assembling a ``DecisionTrace`` or pushing
        :meth:`kernel_events` for a named node.

        ``field_contracts`` / ``consumption_attested`` are the kernel's
        consumption contracts (``axor_core.kernel.consumption``): per tool, the
        fields its callable reads and how. With a contract the kernel prepares
        each call (defaults, declared conversions, closed field set) before any
        gate, and the callable is invoked with THAT prepared set — the arguments
        the kernel judged — never with the model's raw proposal. Tools without a
        contract run with their arguments unchanged."""
        self._tools = dict(tools)
        self.manifests = list(manifests)
        self.policy = dict(policy) if policy else None
        self.inputs = dict(inputs) if inputs else None
        self.config = governor_kwargs(self.manifests, policy, inputs)
        # Tools whose execution MUST use the kernel's prepared arguments. For
        # these there is no fallback to the raw proposal (see `call`).
        self._contracted = frozenset(field_contracts or ())
        if field_contracts or consumption_attested:
            if governor is not None:
                raise ValueError(
                    "field_contracts / consumption_attested configure the governor this "
                    "toolset builds; an injected governor would not apply them — pass "
                    "them to that governor instead"
                )
            _require_contract_kernel()
        if field_contracts:
            self.config["field_contracts"] = dict(field_contracts)
        if consumption_attested:
            self.config["consumption_attested"] = set(consumption_attested)
        self.node_id = node_id
        # node_id is the governor's, not part of the compiled governance
        # contract — keeping it out of `config` keeps `config` comparable
        # between two runs of the same contract on different nodes.
        self._governor = (
            governor if governor is not None
            else _build_governor({**self.config, "node_id": node_id})
        )
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
        read this one feed; neither gets its own instrumentation. Defaults to
        this toolset's ``node_id``, so a caller that named its node at
        construction does not have to name it again here (and cannot name it
        differently by accident).
        """
        from axor_wrap.plane.bridge import trace_to_kernel

        node = node_id if node_id is not None else (self.node_id or None)
        return list(trace_to_kernel(self.trace_events, node))  # type: ignore[arg-type]

    def callables(self) -> dict[str, Callable[..., object]]:
        """This toolset as drop-in ``{name: callable}``, all sharing THIS session.

        The second surface of the one wrap: :meth:`call` for a loop the caller
        owns, this for a framework that owns its own invocation loop (LangChain,
        an MCP server, an eval harness that hands an agent a tool dict). Same
        governor, same ledger, same enforcement flag, same recorder — the trace
        comes off this object afterwards either way.

        ``wrap_callables`` is the one-liner for when the toolset itself is not
        needed; keep the toolset when it is (``record=True`` and you want
        :meth:`trace`, or a Control-Plane admission bound later).
        """
        def _make(name: str) -> Callable[..., object]:
            fn = self._tools[name]

            @functools.wraps(fn)
            def wrapped(**kwargs: object) -> object:
                return self.call(name, kwargs)

            return wrapped

        return {name: _make(name) for name in self._tools}

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
        # The argument set the kernel judged. For a tool with a consumption
        # contract it is the prepared set (defaults materialised, declared
        # conversions applied) and it is the ONLY set that may reach the
        # callable: executing the raw proposal instead would run a value no gate
        # saw. A denial carries no prepared set; the observe-only arm below then
        # runs what the agent proposed, because that is what an ungoverned agent
        # would have run.
        judged = getattr(decision, "args", None)
        if judged is None and decision.allowed and name in self._contracted:
            # A contract was requested and the kernel did not hand back what it
            # judged. Executing the raw proposal would run a value no gate checked.
            raise KernelIncompatibleError(
                f"tool {name!r} has a consumption contract but the kernel returned no "
                f"prepared arguments — refusing to execute the raw proposal"
            )
        call_args = dict(judged) if judged is not None else dict(args)
        # recorded at the moment the kernel is consulted, so the recorder stays
        # 1:1 and in order with the kernel's own events — and with the argument
        # set those events name. A call refused before this line (unknown tool,
        # admission held) produced no verdict either.
        recorded = self._recorder.evaluated(name, call_args) if self._recorder else None
        if not decision.allowed and self.enforcement == ENFORCEMENT_ON:
            raise ToolDenied(decision.reason, decision.category)
        # observe-only: the verdict is recorded and reported, the call proceeds.
        # register_output still runs, so a denied-but-executed call's output
        # taints the ledger exactly as it would have — which is the whole point
        # of measuring what an UNGOVERNED agent actually does.
        # An observe-only DENY runs what the agent proposed (an unwrapped agent's
        # call), recorded apart from the checked set; an ALLOW runs the checked set.
        bypassed = not decision.allowed
        executed_args = dict(args) if bypassed else call_args
        output = self._tools[name](**executed_args)
        self._governor.register_output(decision, output)  # type: ignore[attr-defined]
        if recorded is not None:
            recorded.executed, recorded.result = True, output
            recorded.executed_args = executed_args
            recorded.enforcement_bypassed = bypassed
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
    enforcement: str = ENFORCEMENT_ON,
    record: bool = False,
    inputs: dict[str, object] | None = None,
    node_id: str = "",
    field_contracts: dict[str, object] | None = None,
    consumption_attested: "set[str] | frozenset[str] | None" = None,
) -> dict[str, Callable[..., object]]:
    """Wrapped drop-in callables sharing ONE governor session.

    For frameworks that own their own invocation loop: hand these to LangChain /
    an MCP server instead of the raw functions; each call is gated exactly like
    ``WrappedToolset.call`` and raises ``ToolDenied`` on a kernel deny (or
    ``AdmissionHeld`` when a bound Control-Plane node is paused/stopped).

    ``enforcement="off"`` observes without blocking — the same UNGOVERNED arm
    ``WrappedToolset`` documents. It is here because this is the surface a
    harness that hands an agent a tool dict actually uses, and a harness that
    could not ask for observe-only had to reimplement the gate to get it.

    ``record=True`` keeps raw arguments and results, but this function returns
    only the callables and so gives no way to read them back: build a
    ``WrappedToolset`` and call :meth:`WrappedToolset.callables` when you want
    the trace afterwards.
    """
    toolset = WrappedToolset(
        tools, manifests, policy=policy, governor=governor, admission=admission,
        enforcement=enforcement, record=record, inputs=inputs, node_id=node_id,
        field_contracts=field_contracts, consumption_attested=consumption_attested,
    )
    return toolset.callables()
