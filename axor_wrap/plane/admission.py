"""PlaneAdmission — drives an IntentLoop from a PlaneSession's posture.

Implements the AdmissionController contract over a :class:`PlaneSession` whose
state is updated out-of-band by the plane client's SSE subscription. Pausing
holds here (the node has already finished its current intent — the boundary is
between intents); stopping returns False so the loop winds down like a
cancellation. A disconnected plane never blocks: the session simply stays in
its last posture, and with no pause/stop set the node runs under local config.
"""
from __future__ import annotations

import asyncio

from axor_wrap.plane.session import PlaneSession


class PlaneAdmission:
    def __init__(self, session: PlaneSession, poll_interval: float = 0.05) -> None:
        self._session = session
        self._poll = poll_interval
        # Pulsed by notify() when the session posture changes, so a paused loop
        # resumes promptly instead of waiting out the poll interval.
        self._changed = asyncio.Event()

    def notify(self) -> None:
        """Signal that the session posture changed (call after applying a
        delta). Safe to call from the client's SSE task."""
        self._changed.set()

    async def await_admission(self, node_id: str) -> bool:
        while True:
            if self._session.stopped:
                return False
            if not self._session.paused:
                return True
            self._changed.clear()
            try:
                await asyncio.wait_for(self._changed.wait(), self._poll)
            except TimeoutError:
                pass  # re-poll: posture may have changed without a notify()

    # ── ControlDirectives (axor-core >= 0.12.1) ───────────────────────────────
    #
    # The operator's one-shot effects. The session already verified each
    # command's signature and queued it; until axor-core 0.12.1 nothing in the
    # kernel asked for them, so an excision sat here forever and a heal waited
    # on a re-probe of a context nobody had cut. The kernel now asks at its own
    # boundaries; these hand over what is queued, and the session's outbox
    # tells the plane it was consumed (`context_excision`, `injection_consumed`)
    # — which is what closes the operator's heal.
    #
    # Core types are imported here, not at module top: this adapter still
    # supports kernels older than the contract, and only a kernel that has it
    # calls these.

    def take_excision(self, provenance):  # noqa: ANN001, ANN201 - core types, lazily
        from axor_core.contracts.degradation import GovernanceAuthority
        from axor_core.contracts.directives import ExcisionDirective

        exc = self._session.take_pending_excision(dict(provenance))
        if exc is None:
            return None
        return ExcisionDirective(
            excision_id=exc.excision_id,
            target_refs=tuple(exc.target_refs),
            # the operator whose signature the session verified (or the
            # unsigned posture an open deployment runs) — built HERE, by the
            # party that checked it, never by the kernel's worker path
            authority=GovernanceAuthority(
                authority_id=exc.operator or "plane-operator",
                authority_type="human_operator",
                reason_code=exc.reason or "operator excision",
                audit_id=exc.excision_id,
            ),
        )

    def take_injection(self):  # noqa: ANN201 - core type, lazily
        from axor_core.contracts.directives import InjectionDirective

        inj = self._session.take_pending_injection()
        if inj is None:
            return None
        return InjectionDirective(
            injection_id=inj.injection_id, text=inj.text, operator=inj.operator,
        )

    def budget_cap_calls(self) -> int | None:
        """The session's cap: the adapter's local one, lowered by any operator
        command (the session already refuses a widening)."""
        return self._session.budget_cap_calls

