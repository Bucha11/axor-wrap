"""Connectors — one wrap serves both products.

``LabRuntimeConnector`` speaks axor-lab's runtime-jobs protocol
(``lab_server/runtime_jobs.py``, spec v0.3): **Lab assigns, the runtime
executes.** The wrapped runtime registers once, then pulls assignments, streams
kernel events, and pushes finished traces:

    POST /runtimes/connect                              → {runtime_ref, ingest_key}
    GET  /runtime/jobs                                  (Bearer ingest_key) poll
    POST /runtime/jobs/{id}/claim                       claim → the assignment
    POST /runtime/jobs/{id}/trials/{tid}/events         stream kernel events
    POST /runtime/jobs/{id}/trials/{tid}/complete       finalize (uploads trace)

Deliberately synchronous and minimal (stdlib ``urllib``): the runtime-jobs
server is a polling contract, and keeping this connector dependency-free keeps
the whole wrap engine stdlib-only.

``PlaneConnector`` is the Control-Plane seam — a REAL governed-node connection
built on this package's own plane primitives (``axor_wrap.plane``:
``PlaneSession`` / ``PlaneClient``, which in turn reason over axor-core's kernel
primitives — the desired-state lattice, JCS canonical bytes, the event schema):
the node registers, heartbeats (so Control's topology shows it live with its level),
and subscribes to desired state over SSE — so an operator's pause / stop / budget
reaches the node and is applied to the session posture (and, when bound with
``gate``, actually holds the wrapped runtime's tool calls).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import urllib.error
import urllib.request
from typing import TYPE_CHECKING

from axor_wrap.errors import ConnectorError, PlaneExtraNotInstalledError

if TYPE_CHECKING:
    from axor_wrap.plane.client import PlaneClient
    from axor_wrap.plane.session import PlaneSession

    from axor_wrap.runtime import WrappedToolset

_DEFAULT_TIMEOUT_S = 10.0


class LabRuntimeConnector:
    """A connected runtime for axor-lab's runtime-jobs server."""

    def __init__(
        self,
        base_url: str,
        *,
        control_token: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT_S,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._control_token = control_token
        self._timeout = timeout
        self.runtime_ref: str | None = None
        self.ingest_key: str | None = None

    # ── registration (control surface) ───────────────────────────────────────

    def connect(self, runtime_label: str = "", agent_ref: str | None = None) -> dict[str, object]:
        """POST /runtimes/connect → stores and returns {runtime_ref, ingest_key}.

        `runtime_label` is a free-form display name for this connection; Lab does
        not call any model — this runtime makes its own inference calls and posts
        results back. The label only helps identify the connection in the UI.
        """
        body: dict[str, object] = {"runtime_label": runtime_label}
        if agent_ref is not None:
            body["agent_ref"] = agent_ref
        payload = self._request("POST", "/runtimes/connect", body, token=self._control_token)
        self.runtime_ref = str(payload["runtime_ref"])
        self.ingest_key = str(payload["ingest_key"])
        return payload

    # ── runtime-facing surface (Bearer ingest_key) ───────────────────────────

    def poll_jobs(self) -> list[dict[str, object]]:
        """GET /runtime/jobs → the claimable assignments for this runtime."""
        payload = self._request("GET", "/runtime/jobs", token=self._require_key())
        return list(payload.get("jobs", []))  # type: ignore[arg-type]

    def claim(self, job_id: str) -> dict[str, object]:
        """POST /runtime/jobs/{id}/claim → the assignment + planned trials."""
        return self._request("POST", f"/runtime/jobs/{job_id}/claim", {},
                             token=self._require_key())

    def post_events(
        self, job_id: str, trial_id: str, events: list[dict[str, object]],
    ) -> dict[str, object]:
        """Stream a batch of kernel events into one trial."""
        return self._request(
            "POST", f"/runtime/jobs/{job_id}/trials/{trial_id}/events",
            {"events": events}, token=self._require_key(),
        )

    def complete_trial(
        self,
        job_id: str,
        trial_id: str,
        trace: dict[str, object] | None,
        status: str = "completed",
        metrics: dict[str, object] | None = None,
        runtime_config_hash: str | None = None,
    ) -> dict[str, object]:
        """Finalize one trial, uploading its finished trace.

        ``metrics`` carries what only this runtime could measure about the
        trial — wall-clock, steps, tokens, spend. It travels BESIDE the trace
        rather than inside it: ``trace/v1`` describes what the KERNEL saw and
        decided, while cost and latency are the runtime's own measurements.

        Build the trace with ``WrappedToolset.trace()`` — the wrapped session
        already holds everything it needs.

        Omit it and Lab records no measurements for the trial, which is honest
        but leaves a latency or budget invariant unevaluable — Lab does not
        time a run on someone else's machine, and it will not invent a number
        it did not observe.
        """
        body: dict[str, object] = {"trace": trace, "status": status}
        if metrics:
            body["metrics"] = metrics
        if runtime_config_hash:
            body["runtime_config_hash"] = runtime_config_hash
        return self._request(
            "POST", f"/runtime/jobs/{job_id}/trials/{trial_id}/complete",
            body, token=self._require_key(),
        )

    # ── transport ────────────────────────────────────────────────────────────

    def _require_key(self) -> str:
        if not self.ingest_key:
            raise ConnectorError(0, "not connected — call connect() first")
        return self.ingest_key

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, object] | None = None,
        *,
        token: str | None = None,
    ) -> dict[str, object]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(self.base_url + path, data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            try:
                detail = str(json.loads(detail).get("error", detail))
            except ValueError:
                pass
            raise ConnectorError(exc.code, detail or exc.reason) from exc
        except urllib.error.URLError as exc:
            raise ConnectorError(0, f"cannot reach {self.base_url}: {exc.reason}") from exc
        try:
            payload = json.loads(raw or b"{}")
        except ValueError as exc:
            raise ConnectorError(0, f"non-JSON response from {path}") from exc
        if not isinstance(payload, dict):
            raise ConnectorError(0, f"unexpected response shape from {path}")
        return payload


def _plane_types() -> tuple[type[PlaneClient], type[PlaneSession]]:
    """Lazily import the plane primitives, turning a missing extra into an
    honest ``PlaneExtraNotInstalledError`` instead of a raw ``ImportError``."""
    try:
        from axor_wrap.plane.client import PlaneClient
        from axor_wrap.plane.session import PlaneSession
    except ImportError as exc:  # pragma: no cover - import guard
        raise PlaneExtraNotInstalledError() from exc
    return PlaneClient, PlaneSession


class PlaneConnector:
    """A live governed node on the Control Plane, for a wrapped runtime.

    Built on :mod:`axor_wrap.plane` (extra ``axor-wrap[plane]``) — this is NOT a
    protocol fork. On :meth:`connect` the node builds a :class:`PlaneSession`
    (adapter-local posture, operator-key verification) and a :class:`PlaneClient`
    (outbound-only SSE + telemetry). :meth:`run` heartbeats — so Control's
    topology shows the node live with a level that mirrors its posture
    (``NORMAL`` / ``CAUTIOUS`` when paused / ``RESTRICTED`` when stopped) — and
    subscribes to desired state, so an operator command (pause / stop / budget
    cap) is applied to the session by real protocol code — verified against
    operator keys from LOCAL config, folded through axor-core's desired-state
    lattice and provenance guard.

    Bind the node to a :class:`~axor_wrap.runtime.WrappedToolset` with
    :meth:`gate`: the toolset then polls :meth:`admit` at each call, so a
    Control-Plane pause/stop actually holds the wrapped agent's real tool
    execution (``AdmissionHeld``) — not just a flag on the session.

    Scope (honest boundary): this is the connection + posture-gating half. The
    full IntentLoop-admission path (one-shot injection / excision / replan winding
    an ``IntentLoop`` down at the intent boundary) needs the framework to hand
    axor-core an ``Invokable`` agent brain — which the wrap model, gating tools
    while the framework owns the loop, does not provide. That path is
    ``GovernedSession(executor=Invokable, admission=PlaneAdmission(session))``.
    """

    def __init__(
        self,
        backend_url: str,
        node_id: str,
        *,
        operator_keys: dict[str, str] | None = None,
        run_id: str | None = None,
        local_budget_cap: int | None = None,
        test_bench: bool = False,
        heartbeat_period: float = 10.0,
        ingest_key: str | None = None,
    ) -> None:
        self.backend_url = backend_url.rstrip("/")
        self.node_id = node_id
        self._operator_keys = dict(operator_keys or {})
        self._run_id = run_id
        self._local_budget_cap = local_budget_cap
        self._test_bench = test_bench
        self._heartbeat_period = heartbeat_period
        # Scoped `ingest` credential for the plane channel. Optional, because a
        # backend with auth off accepts an unauthenticated node; required the
        # moment the operator sets AXOR_API_TOKEN, and best minted bound to this
        # node_id so it cannot speak for its neighbours.
        self._ingest_key = ingest_key
        self.session: PlaneSession | None = None
        self._client: PlaneClient | None = None
        self._stop: asyncio.Event | None = None

    # ── posture (source of truth for level + admission) ───────────────────────

    def _require_session(self) -> PlaneSession:
        if self.session is None:
            raise ConnectorError(0, "not connected — call connect() first")
        return self.session

    def level(self) -> str:
        """Governed level derived from posture, mirrored to Control in every
        heartbeat: an operator pause/stop is visible as a level change."""
        session = self._require_session()
        if session.stopped:
            return "RESTRICTED"
        return "CAUTIOUS" if session.paused else "NORMAL"

    def admit(self) -> bool:
        """Intent-boundary admission — ``False`` once an operator has paused or
        stopped the node. This is axor-core's own ``PlaneSession.admit_intent``."""
        return self._require_session().admit_intent()

    def gate(self, toolset: WrappedToolset) -> WrappedToolset:
        """Bind a wrapped toolset to this node's posture: its ``call`` polls
        :meth:`admit` first, so a Control-Plane pause/stop holds real tool
        execution with ``AdmissionHeld``. Returns the toolset for chaining."""
        self._require_session()
        toolset.set_admission(self.admit)
        return toolset

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def connect(self) -> PlaneConnector:
        """Build the plane session + client (no I/O yet). Raises
        ``PlaneExtraNotInstalledError`` when the plane extra is absent."""
        plane_client_cls, plane_session_cls = _plane_types()
        self.session = plane_session_cls(
            node_id=self.node_id,
            operator_pubkeys=self._operator_keys,
            test_bench=self._test_bench,
            local_budget_cap=self._local_budget_cap,
        )
        self._client = plane_client_cls(
            self.backend_url,
            self.session,
            run_id=self._run_id,
            heartbeat_period=self._heartbeat_period,
            ingest_key=self._ingest_key,
        )
        self._stop = asyncio.Event()
        return self

    async def run(self, ttl: float | None = None) -> None:
        """Keep the node live: an SSE desired-state subscription and a heartbeat
        loop, until :meth:`stop` (or ``ttl`` seconds elapse). The first flush is
        sent up front so the node appears in Control immediately. Applying a
        pushed desired-delta (pause/stop/budget) is real axor-core code —
        ``PlaneClient`` → ``PlaneSession.apply_delta``."""
        if self._client is None or self._stop is None:
            self.connect()
        assert self._client is not None and self._stop is not None
        client, stop = self._client, self._stop

        subscribe = asyncio.create_task(client.run(stop))
        heartbeat = asyncio.create_task(
            client.heartbeat_loop(stop, level_fn=self.level)
        )
        try:
            await client.flush(level=self.level())  # first heartbeat → live now
            if ttl is None:
                await stop.wait()
            else:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), ttl)
        finally:
            stop.set()
            for task in (subscribe, heartbeat):
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    async def post_health_check(self, health_payload: dict) -> bool:
        """Post a finished behavioral health check. True when the plane took it.

        `health_payload` is what ``axor_probe.integration.plane.health_payload``
        returns for a ``ProbeReport``. axor-wrap does not import axor-probe: a
        node that probes hands the dict over, a node that does not never calls
        this, and neither package grows a dependency on the other.

        Batteries are the node's to run and the node's to report — the plane has
        no inbound path into a runtime and a health check is not an exception::

            report = await pipeline.run(event)
            if report is not None:
                await connector.post_health_check(health_payload(report))
        """
        if self._client is None:
            self.connect()
        assert self._client is not None
        return await self._client.post_probe_report(health_payload)

    def stop(self) -> None:
        """Signal :meth:`run` to wind the node down. Idempotent."""
        if self._stop is not None:
            self._stop.set()
