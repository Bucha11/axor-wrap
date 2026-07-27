"""The wrapped runtime — every tool call goes through the real kernel.

``WrappedToolset`` holds ``{name: callable}`` plus the tools' manifests, builds
an ``axor_core.governor.ToolCallGovernor`` from the compiled config, and gates
each call: ``evaluate → (deny → ToolDenied) → call → register_output``. That is
the exact usage contract the governor documents, and the same decision path the
Control Plane and axor-lab's real-kernel backend run.

axor-core is an OPTIONAL dependency (extra ``kernel``): the import is lazy and a
missing install raises ``KernelNotInstalledError`` with the exact pip command.
For frameworks that own their invocation loop (LangChain executors, MCP
servers), ``wrap_callables`` returns drop-in wrapped callables that share one
governor session.
"""

from __future__ import annotations

import functools
from typing import Callable

from axor_wrap.compile import governor_kwargs
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
    ) -> None:
        """``governor`` overrides construction (tests / custom kernels); otherwise
        the governor is built lazily-imported from axor-core with the kwargs
        compiled from ``manifests`` (+ optional ``policy`` allowlist).

        ``admission`` is an optional zero-arg predicate polled at the intent
        boundary (before the governor runs) — ``False`` means an operator has
        paused/stopped this node, and the call is held with ``AdmissionHeld``.
        ``PlaneConnector.gate`` wires this to a live ``PlaneSession``, so a
        Control-Plane pause/stop actually halts real tool execution."""
        self._tools = dict(tools)
        self.manifests = list(manifests)
        self.config = governor_kwargs(self.manifests, policy)
        self._governor = governor if governor is not None else _build_governor(self.config)
        self._admission = admission

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
        if not decision.allowed:
            raise ToolDenied(decision.reason, decision.category)
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
