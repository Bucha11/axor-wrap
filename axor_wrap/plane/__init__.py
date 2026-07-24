"""Control-plane primitives — the adapter (node) side of the advisory overlay.

These live HERE, not in axor-core, and that placement is the architecture:

- **axor-core owns the primitives the plane reasons over** — the desired-state
  lattice and its provenance guard (``axor_core.kernel.state``: ``DesiredState``,
  ``Injection``, ``Excision``, ``excision_refused_refs``), the canonical byte
  form commands are signed over (``axor_core.kernel.jcs.canonicalize``), the
  event schema telemetry speaks (``axor_core.kernel.events``), and the pure
  ``AdmissionController`` contract the loop steers through
  (``axor_core.contracts.admission``). None of that is plane-specific: the
  kernel enforces against it whether or not a plane is ever attached.

- **axor-wrap owns everything plane-*specific*** — the session semantics that
  keep a compromised backend harmless (:class:`PlaneSession`), the transport
  that dials out to it (:class:`PlaneClient`), the admission implementation that
  binds a posture to a running loop (:class:`PlaneAdmission`), and the trace →
  kernel-event projection the telemetry direction ships
  (:func:`trace_to_kernel`).

The reason for the split is the one guarantee that matters: enforcement is local
and in-process, and the plane is an advisory overlay that can only *narrow*
(spec 12.0). A kernel that cannot import a plane client cannot grow a dependency
on one, so "the plane is not in the decision path" stops being a review
convention and becomes a packaging fact — axor-core has zero required
dependencies and no network surface at all.

Requires the ``plane`` extra (``pip install 'axor-wrap[plane]'``) for
:class:`PlaneClient` I/O (httpx) and command signature verification
(cryptography). :class:`PlaneSession` semantics work without either.
"""
from axor_wrap.plane.admission import PlaneAdmission
from axor_wrap.plane.bridge import trace_event_to_kernel, trace_to_kernel
from axor_wrap.plane.session import AppliedEffect, PlaneSession

__all__ = [
    "AppliedEffect",
    "PlaneAdmission",
    "PlaneSession",
    "trace_event_to_kernel",
    "trace_to_kernel",
]
