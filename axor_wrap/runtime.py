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

from axor_wrap.compile import governor_kwargs

ENFORCEMENT_ON = "on"
ENFORCEMENT_OFF = "off"
from axor_wrap.errors import (
    AdmissionHeld,
    KernelNotInstalledError,
    ToolDenied,
    UnknownToolError,
)


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
        from ungoverned to governed is this flag and nothing else."""
        self._tools = dict(tools)
        self.manifests = list(manifests)
        self.config = governor_kwargs(self.manifests, policy)
        self._governor = governor if governor is not None else _build_governor(self.config)
        self._admission = admission
        if enforcement not in (ENFORCEMENT_ON, ENFORCEMENT_OFF):
            raise ValueError(
                f"enforcement must be {ENFORCEMENT_ON!r} or {ENFORCEMENT_OFF!r}, "
                f"got {enforcement!r}"
            )
        self.enforcement = enforcement
        # every decision the governor reached, in call order — including the
        # ones observe-only did not act on. Without this an ungoverned run would
        # have nothing to report, and its trace could not carry the verdicts
        # that make it replayable.
        self.decisions: list[object] = []

    @property
    def tool_names(self) -> tuple[str, ...]:
        return tuple(self._tools)

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
        self.decisions.append(decision)
        if not decision.allowed and self.enforcement == ENFORCEMENT_ON:
            raise ToolDenied(decision.reason, decision.category)
        # observe-only: the verdict is recorded and reported, the call proceeds.
        # register_output still runs, so a denied-but-executed call's output
        # taints the ledger exactly as it would have — which is the whole point
        # of measuring what an UNGOVERNED agent actually does.
        output = self._tools[name](**args)
        self._governor.register_output(decision, output)  # type: ignore[attr-defined]
        return output


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
