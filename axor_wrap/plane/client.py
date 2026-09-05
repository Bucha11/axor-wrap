"""PlaneClient: the outbound-only transport around :class:`PlaneSession`.

The adapter dials out (protocol section 1): an SSE subscription for desired
state and batched telemetry POSTs. Zero listening sockets on user
infrastructure. Channel loss is survivable by construction: enforcement is
local, commands are best-effort, and an optional ``hold_on_disconnect`` pauses
the node locally after a grace period (adapter config — the backend can
neither cause nor prevent it, protocol section 7).

Requires the ``plane`` extra (httpx): axor-wrap's scanner/compiler core — and
axor-core underneath it — stay dependency-free.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from collections.abc import Callable

from axor_wrap.plane.session import PlaneSession

log = logging.getLogger("axor.wrap.plane")

HEARTBEAT_PERIOD = 10.0  # protocol section 9: static T=10s, stale=3T
# Minimum gap between desired-state reconnections, so a stream that ends
# instantly cannot become a reconnect storm.
RECONNECT_DELAY = 1.0
_TELEMETRY_ATTEMPTS = 3   # in-flush retries before falling back to the spool


class _AuthRejected(Exception):
    """The plane refused this node's credential (401/403)."""

    def __init__(self, status: int) -> None:
        super().__init__(f"plane rejected the node credential: {status}")
        self.status = status


def _httpx():  # noqa: ANN202 - module import guard
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - import guard
        raise ImportError(
            "the plane client needs httpx — install the plane extra: "
            "pip install 'axor-wrap[plane]'"
        ) from exc
    return httpx


class PlaneClient:
    def __init__(
        self,
        backend_url: str,
        session: PlaneSession,
        run_id: str | None = None,
        on_fact: Callable[[dict], None] | None = None,
        hold_on_disconnect_after: float | None = None,
        heartbeat_period: float = HEARTBEAT_PERIOD,
        spool_path: str | None = None,
        ingest_key: str | None = None,
    ) -> None:
        self._base = backend_url.rstrip("/")
        self.session = session
        # A run is one process lifetime, and the default run id has to say so.
        # `seq` is this client's counter, starting at zero, and the backend keys
        # an event on (run_id, node_id, seq) — so defaulting the keepalive run to
        # the node id made a restarted process collide with its own predecessor:
        # every event it sent was refused as a duplicate and its telemetry never
        # reached the log again. Explicit run ids are untouched; the suffix only
        # affects the default.
        self._run_id = run_id or f"{session.node_id}-{uuid.uuid4().hex[:8]}"
        self._on_fact = on_fact
        self._hold_after = hold_on_disconnect_after
        self._heartbeat_period = heartbeat_period
        # Telemetry direction owns durability (protocol §5): unsent acks survive
        # a channel outage in memory, and — if a spool path is given — across a
        # process restart. None keeps axor-core's zero-config default (in-memory
        # only), which is what a short-lived run wants.
        self._spool_path = spool_path
        # Credential for the plane channel. The backend's auth is opt-in (unset
        # AXOR_API_TOKEN = open), and this client sent nothing at all — so the
        # moment an operator turned auth ON, every governed node's telemetry,
        # desired-state subscription and health check started answering 401 and
        # the whole channel went quiet. Quiet is exactly what a plane cannot be:
        # a node that cannot heartbeat looks identical to a node that died.
        #
        # A scoped `ingest` key, ideally bound to THIS node (the backend refuses
        # a bound key posting as any other), is what belongs here — never the
        # operator master token, which the node has no business holding.
        self._ingest_key = ingest_key
        self._seq = 0

    def _auth(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Headers for one plane call: the bearer when configured, plus extras.

        Absent a key the headers are empty, which is correct against a backend
        with auth off — the open dev posture — and honestly a 401 against one
        with auth on.
        """
        headers = dict(extra or {})
        if self._ingest_key:
            headers["Authorization"] = f"Bearer {self._ingest_key}"
        return headers

    # ── telemetry ─────────────────────────────────────────────────────────────

    async def flush(
        self, extra_events: list[dict] | None = None,
        level: str = "NORMAL", budget_remaining: int | None = None,
    ) -> None:
        """POST the durable events (outbox + anything spooled from a failed
        earlier flush) plus a heartbeat, as one idempotent batch.

        Durability is the point (protocol §5): the outbox is NOT cleared until
        the POST is acknowledged. On failure the durable events are held — in
        memory, and on disk if a spool path was configured — and retried on the
        next flush, so an operator ack (injection_consumed, context_excision) is
        never dropped because the backend blinked."""
        httpx = _httpx()
        # Move the durable events out of the outbox up front, but keep a hold on
        # them so a failed POST can put them back.
        durable = self._load_spool() + list(self.session.outbox)
        self.session.outbox.clear()
        heartbeat = self.session.heartbeat(level, budget_remaining)
        events = durable + list(extra_events or []) + [heartbeat]
        lines = [self._line(e) for e in events]
        try:
            await self._post_telemetry(httpx, lines)
        except httpx.HTTPError:
            # Hold the durable events (not the heartbeat — it is regenerated, and
            # not caller-owned extra_events) for the next flush. With a spool
            # configured they survive a process restart; without one they go back
            # to the front of the in-memory outbox. Either way, nothing is lost.
            if self._spool_path:
                self._save_spool(durable)
            else:
                self.session.outbox[:0] = durable
            return
        self._save_spool([])  # delivered — clear any prior spool
        for e in events:
            if e["kind"] in ("injection_consumed", "context_excision"):
                key = ("pending_injection" if e["kind"] == "injection_consumed"
                       else "pending_excision")
                try:
                    async with httpx.AsyncClient(timeout=15.0) as client:
                        await client.post(
                            f"{self._base}/v1/plane/{self.session.node_id}/consumed",
                            json={"key": key}, headers=self._auth(),
                        )
                except httpx.HTTPError:
                    pass  # best-effort; the ack itself was already delivered

    async def _post_telemetry(self, httpx, lines: list[dict]) -> None:  # noqa: ANN001
        """POST the batch, retrying transient failures with backoff. The
        Idempotency-Key makes a retried batch a no-op backend-side."""
        key = uuid.uuid4().hex
        backoff = 0.5
        last: Exception | None = None
        for attempt in range(_TELEMETRY_ATTEMPTS):
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    response = await client.post(
                        f"{self._base}/v1/plane/{self.session.node_id}/telemetry",
                        json={"run_id": self._run_id, "events": lines},
                        headers=self._auth({"Idempotency-Key": key}),
                    )
                    response.raise_for_status()
                return
            except httpx.HTTPError as exc:
                last = exc
                if attempt < _TELEMETRY_ATTEMPTS - 1:
                    await asyncio.sleep(backoff)
                    backoff *= 2
        raise last  # type: ignore[misc]

    # ── behavioral health checks (axor-probe batteries) ───────────────────────

    async def post_probe_report(self, payload: dict) -> bool:
        """POST one finished health check out-dial. True when the plane took it.

        `payload` is axor-probe's ``integration.plane.health_payload(report)``.
        The dict is the entire contract: axor-wrap does not import axor-probe,
        so a node can run batteries without the wrapper knowing how, and the
        wrapper can transport them without depending on the prober.

        Out-dial like everything else on this channel — the plane never reaches
        into the runtime to start a battery, so posting the result is the node's
        move, not the plane's.

        A lost check is not a lost operator ack, so this does not spool: the next
        battery supersedes this one, and pretending otherwise would leave stale
        verdicts on disk to be posted later as if fresh. Transient failures are
        retried and then reported as False. A 4xx is a malformed payload — a
        programming error, not weather — and raises.
        """
        httpx = _httpx()
        backoff = 0.5
        for attempt in range(_TELEMETRY_ATTEMPTS):
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    response = await client.post(
                        f"{self._base}/v1/plane/{self.session.node_id}/probe-report",
                        json=payload, headers=self._auth(),
                    )
                    response.raise_for_status()
                return True
            except httpx.HTTPStatusError as exc:
                if 400 <= exc.response.status_code < 500:
                    raise
                if attempt == _TELEMETRY_ATTEMPTS - 1:
                    return False
            except httpx.HTTPError:
                if attempt == _TELEMETRY_ATTEMPTS - 1:
                    return False
            await asyncio.sleep(backoff)
            backoff *= 2
        return False

    def _load_spool(self) -> list[dict]:
        if not self._spool_path or not os.path.exists(self._spool_path):
            return []
        with open(self._spool_path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def _save_spool(self, events: list[dict]) -> None:
        if not self._spool_path:
            return
        if not events:
            if os.path.exists(self._spool_path):
                os.remove(self._spool_path)
            return
        tmp = f"{self._spool_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            for e in events:
                fh.write(json.dumps(e) + "\n")
        os.replace(tmp, self._spool_path)  # atomic swap

    async def heartbeat_loop(
        self, stop: asyncio.Event,
        level_fn: Callable[[], str] | None = None,
        budget_fn: Callable[[], int | None] | None = None,
    ) -> None:
        """Emit a heartbeat every T seconds until `stop` (protocol §9). The
        backend marks a node stale after 3T of silence, so this loop existing is
        what keeps a healthy node out of the stale set. Never raises: flush owns
        its own durability, and a heartbeat we could not send is retried next
        tick."""
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), self._heartbeat_period)
                return
            except TimeoutError:
                pass
            level = level_fn() if level_fn is not None else "NORMAL"
            budget = budget_fn() if budget_fn is not None else None
            try:
                await self.flush(level=level, budget_remaining=budget)
            except Exception:  # noqa: BLE001 - the loop must outlive any flush error
                pass

    def _line(self, event: dict) -> dict:
        from datetime import UTC, datetime

        seq = self._seq
        self._seq += 1
        return {
            "schema_version": "1.0",
            "seq": seq,
            "node_id": self.session.node_id,
            "kind": event["kind"],
            "ts": datetime.now(UTC).isoformat(),
            "causal_root": None,
            "gate": None,
            "verdict": None,
            "payload": event.get("payload", {}),
        }

    # ── downstream subscription ───────────────────────────────────────────────

    async def _pause(self, stop: asyncio.Event, seconds: float) -> bool:
        """Wait `seconds` or until `stop`. True when it is time to give up."""
        try:
            await asyncio.wait_for(stop.wait(), seconds)
        except TimeoutError:
            return False
        return True

    async def run(self, stop: asyncio.Event) -> None:
        """Subscribe to desired state until `stop` is set. Reconnects with
        backoff; fail-continue under local config on channel loss."""
        httpx = _httpx()
        backoff = 1.0
        while not stop.is_set():
            try:
                async with httpx.AsyncClient(timeout=None) as client, client.stream(
                    "GET", f"{self._base}/v1/plane/{self.session.node_id}/desired",
                    headers=self._auth(),
                ) as response:
                    if response.status_code in (401, 403):
                        # A rejected credential is not weather: retrying with
                        # backoff forever would leave the node running under
                        # stale desired state while looking merely disconnected.
                        # Say it once per attempt, loudly, and keep the backoff
                        # so a key rotated back in is picked up without a
                        # restart.
                        log.error(
                            "plane rejected this node's credential (%s) on the "
                            "desired-state subscription — the node is running "
                            "on its LAST APPLIED state and operator commands "
                            "are not reaching it. Check the ingest key: it "
                            "needs the `ingest` scope, and a node-bound key "
                            "may only speak for %r.",
                            response.status_code, self.session.node_id,
                        )
                        raise _AuthRejected(response.status_code)
                    backoff = 1.0
                    await self._consume_sse(response, stop)
                # The stream ended with no error: the backend closed it, or an
                # intermediary timed the connection out. Reconnect — but never
                # in a tight loop. A stream that ends immediately (a 200 with an
                # empty body, a proxy that does not speak SSE) would otherwise
                # spin the event loop and reconnect as fast as the backend can
                # answer, which is a self-inflicted denial of service on the
                # one channel that carries operator commands.
                if await self._pause(stop, RECONNECT_DELAY):
                    return
            except _AuthRejected:
                if await self._pause(stop, backoff):
                    return
                backoff = min(backoff * 2, 30.0)
            except httpx.HTTPError:
                if self._hold_after is not None:
                    if await self._pause(stop, self._hold_after):
                        return
                    self.session.paused = True  # hold_on_disconnect opted in
                else:
                    if await self._pause(stop, backoff):
                        return
                    backoff = min(backoff * 2, 30.0)

    async def _consume_sse(self, response, stop: asyncio.Event) -> None:  # noqa: ANN001
        event_name = ""
        data_lines: list[str] = []
        async for raw in response.aiter_lines():
            if stop.is_set():
                return
            line = raw.rstrip("\n")
            if line.startswith("event:"):
                event_name = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].strip())
            elif line == "" and data_lines:
                self._dispatch(event_name, json.loads("\n".join(data_lines)))
                event_name, data_lines = "", []

    def _dispatch(self, event_name: str, data: dict) -> None:
        if event_name == "snapshot":
            self.session.apply_snapshot(int(data["version"]), data.get("state", {}))
        elif event_name == "delta":
            self.session.apply_delta(
                int(data["version"]), data.get("delta", data.get("state", {})),
                data.get("operator", ""), data.get("timestamp", ""),
                data.get("sig", ""),
            )
        elif event_name == "fact" and self._on_fact is not None:
            self._on_fact(data.get("fact", {}))
