"""The plane channel presents a credential (control-plane audit, F-21).

The backend's auth is opt-in: unset AXOR_API_TOKEN and everything is open, set
it and every /v1/plane route needs a bearer. This client sent no credential at
all on ANY of its calls — telemetry, the desired-state subscription, the
one-shot consumption ack, the health check. So the moment an operator turned
auth on, every governed node's channel started answering 401 and went quiet,
which is the one thing a plane cannot be: a node that cannot heartbeat is
indistinguishable from a node that died.

It also made the backend's node-binding (a key that may only speak for its own
node) unusable — there was no way for a node to present a key at all.
"""
from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("httpx")

import httpx  # noqa: E402

from axor_wrap.plane.client import PlaneClient  # noqa: E402
from axor_wrap.plane.session import PlaneSession  # noqa: E402

KEY = "ak_dead.beef"


class _Recorder:
    """Captures every request the client makes, and answers 200."""

    def __init__(self) -> None:
        self.seen: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        if request.url.path.endswith("/desired"):
            return httpx.Response(200, text="")
        return httpx.Response(200, json={"stored": 1})

    def bearer_for(self, suffix: str) -> str | None:
        for r in self.seen:
            if r.url.path.endswith(suffix):
                return r.headers.get("authorization")
        return None


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    rec = _Recorder()
    real = httpx.AsyncClient

    def patched(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(rec.handler)
        return real(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", patched)
    return rec


def test_telemetry_carries_the_bearer(recorder: _Recorder) -> None:
    session = PlaneSession(node_id="n0")
    client = PlaneClient("http://backend.test", session, ingest_key=KEY)
    asyncio.run(client.flush())
    assert recorder.bearer_for("/telemetry") == f"Bearer {KEY}"


def test_probe_report_carries_the_bearer(recorder: _Recorder) -> None:
    """The health channel is a plane write like any other — it was the one most
    likely to be missed, because a node can run for a long time without one."""
    client = PlaneClient("http://backend.test", PlaneSession(node_id="n0"),
                         ingest_key=KEY)
    assert asyncio.run(client.post_probe_report({"overall_verdict": "CONSISTENT"}))
    assert recorder.bearer_for("/probe-report") == f"Bearer {KEY}"


def test_consumption_ack_carries_the_bearer(recorder: _Recorder) -> None:
    """The ack that clears a one-shot injection/excision is a separate POST,
    and it is the one whose loss silently re-fires an operator's action."""
    session = PlaneSession(node_id="n0")
    session.outbox.append(
        {"kind": "injection_consumed", "payload": {"id": "inj1"}}
    )
    client = PlaneClient("http://backend.test", session, ingest_key=KEY)
    asyncio.run(client.flush())
    assert recorder.bearer_for("/consumed") == f"Bearer {KEY}"


def test_desired_subscription_carries_the_bearer(recorder: _Recorder) -> None:
    session = PlaneSession(node_id="n0")
    client = PlaneClient("http://backend.test", session)
    client._ingest_key = KEY  # noqa: SLF001 - exercising the transport directly
    stop = asyncio.Event()

    async def run_once() -> None:
        task = asyncio.create_task(client.run(stop))
        await asyncio.sleep(0.05)
        stop.set()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(run_once())
    assert recorder.bearer_for("/desired") == f"Bearer {KEY}"


def test_no_key_sends_no_header(recorder: _Recorder) -> None:
    """Against a backend with auth off — the open dev posture — a node without
    a key is correct, and must not start sending an empty bearer."""
    client = PlaneClient("http://backend.test", PlaneSession(node_id="n0"))
    asyncio.run(client.flush())
    assert recorder.bearer_for("/telemetry") is None


def test_a_rejected_credential_is_reported_not_retried_silently(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 401 on the subscription means operator commands are not reaching this
    node while it keeps running on its last applied state. Backing off quietly
    would make that look like an ordinary disconnect."""
    real = httpx.AsyncClient

    def patched(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(
            lambda _r: httpx.Response(401, json={"error": "unauthorized"})
        )
        return real(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", patched)
    client = PlaneClient("http://backend.test", PlaneSession(node_id="n0"),
                         ingest_key="wrong")
    stop = asyncio.Event()

    async def run_once() -> None:
        task = asyncio.create_task(client.run(stop))
        await asyncio.sleep(0.05)
        stop.set()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    with caplog.at_level("ERROR"):
        asyncio.run(run_once())
    assert any("rejected this node's credential" in r.message for r in caplog.records)
