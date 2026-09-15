"""PlaneClient transport: telemetry durability and the heartbeat loop.

The point of these tests is protocol §5 — the telemetry direction owns
durability. A backend that blinks must not cost the operator an ack.
"""
from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("httpx")

from axor_wrap.plane.client import PlaneClient  # noqa: E402
from axor_wrap.plane.session import PlaneSession  # noqa: E402

# Port 1 refuses instantly — a fast, deterministic "backend is down".
DEAD_BACKEND = "http://127.0.0.1:1"


def _session_with_ack() -> PlaneSession:
    s = PlaneSession(node_id="n0")
    s.outbox.append({"kind": "state_applied", "payload": {"version": 1, "result": "x"}})
    return s


def test_spool_roundtrip(tmp_path) -> None:  # noqa: ANN001
    client = PlaneClient(DEAD_BACKEND, PlaneSession(node_id="n0"),
                         spool_path=str(tmp_path / "spool.jsonl"))
    events = [{"kind": "a", "payload": {"x": 1}}, {"kind": "b", "payload": {}}]
    client._save_spool(events)
    assert client._load_spool() == events
    client._save_spool([])  # empty clears the file
    assert client._load_spool() == []


async def test_flush_keeps_outbox_durable_on_failure(tmp_path) -> None:  # noqa: ANN001
    spool = str(tmp_path / "spool.jsonl")
    session = _session_with_ack()
    client = PlaneClient(DEAD_BACKEND, session, spool_path=spool)
    await client.flush()  # backend down — must not raise
    # The outbox was drained, but the ack is not lost: it is on the spool.
    assert session.outbox == []
    spooled = client._load_spool()
    assert len(spooled) == 1 and spooled[0]["kind"] == "state_applied"


async def test_flush_without_spool_holds_events_in_memory() -> None:
    session = _session_with_ack()
    client = PlaneClient(DEAD_BACKEND, session)  # no spool → in-memory only
    await client.flush()  # backend down
    # With no disk spool the unsent ack goes back to the front of the outbox,
    # so the next flush retries it — it is not silently dropped.
    assert [e["kind"] for e in session.outbox] == ["state_applied"]


# ── behavioral health checks (axor-probe batteries) ───────────────────────────

def _health_payload(verdict: str = "DRIFT_DETECTED") -> dict:
    """The shape axor-probe's integration.plane.health_payload emits. Built by
    hand on purpose: the dict IS the contract, and axor-wrap must transport it
    without importing axor-probe."""
    return {
        "session_id": "s1", "agent_id": "a1", "model": "m",
        "probe_library_version": "1.0.0", "overall_verdict": verdict,
        "families": [
            {"family": "data_disclosure", "state": "escaped", "escapes": 1, "probes": 3},
        ],
        "probes_sent": 3, "probes_invalid": 0, "probes_triangulated": 0,
        "structural_failures": 0, "escape_count": 1, "escape_rate": 0.33,
        "escape_rate_ci": [0.0, 0.9], "calibration_status": "UNCALIBRATED",
        "max_drift_score_uncalibrated": 0.6,
    }


async def test_probe_report_posts_to_the_node_path(monkeypatch) -> None:  # noqa: ANN001
    import httpx

    seen: dict = {}

    async def fake_post(self, url, json=None, **kw):  # noqa: ANN001, ANN202, A002
        seen["url"] = url
        seen["json"] = json
        return httpx.Response(201, json={"stored": True, "id": 1},
                              request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    client = PlaneClient("http://plane.test", PlaneSession(node_id="n7"))
    assert await client.post_probe_report(_health_payload()) is True
    assert seen["url"] == "http://plane.test/v1/plane/n7/probe-report"
    # Posted verbatim — the wrapper is transport, it does not reshape verdicts.
    assert seen["json"] == _health_payload()


async def test_probe_report_reports_an_undelivered_check(monkeypatch) -> None:  # noqa: ANN001
    # Backend down. A lost health check is survivable (the next battery
    # supersedes it) so this returns False rather than raising — but it must not
    # claim delivery.
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    client = PlaneClient(DEAD_BACKEND, PlaneSession(node_id="n7"))
    assert await client.post_probe_report(_health_payload()) is False


async def test_probe_report_raises_on_a_malformed_payload(monkeypatch) -> None:  # noqa: ANN001
    import httpx

    attempts = {"n": 0}

    async def fake_post(self, url, json=None, **kw):  # noqa: ANN001, ANN202, A002
        attempts["n"] += 1
        return httpx.Response(400, json={"detail": "overall_verdict must be ..."},
                              request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    client = PlaneClient("http://plane.test", PlaneSession(node_id="n7"))
    with pytest.raises(httpx.HTTPStatusError):
        await client.post_probe_report(_health_payload(verdict="PROBABLY_FINE"))
    # A rejected shape is a programming error, not weather: no retry storm.
    assert attempts["n"] == 1


async def _no_sleep(_seconds: float) -> None:
    """Collapse the retry backoff so the failure paths run at test speed."""
    return None


async def test_heartbeat_loop_ticks_and_stops(monkeypatch) -> None:  # noqa: ANN001
    session = PlaneSession(node_id="n0")
    client = PlaneClient(DEAD_BACKEND, session, heartbeat_period=0.01)
    calls: list[str] = []

    async def fake_flush(**kwargs) -> None:  # noqa: ANN003
        calls.append(kwargs.get("level", "NORMAL"))

    monkeypatch.setattr(client, "flush", fake_flush)
    stop = asyncio.Event()

    async def run() -> None:
        await client.heartbeat_loop(stop, level_fn=lambda: "CAUTIOUS")

    task = asyncio.create_task(run())
    await asyncio.sleep(0.05)
    stop.set()
    await task
    assert calls and all(c == "CAUTIOUS" for c in calls)


def test_the_default_run_id_is_unique_per_process() -> None:
    """A run is one process lifetime, and the default run id has to say so.

    `seq` is a per-client counter starting at zero, and the backend keys an
    event on (run_id, node_id, seq). Defaulting the keepalive run to the node id
    made a restarted process collide with its own predecessor: every event it
    sent was refused as a duplicate, so its telemetry never reached the log
    again — while the node went on reporting a state nothing recorded.
    """
    from axor_wrap.plane.client import PlaneClient
    from axor_wrap.plane.session import PlaneSession

    first = PlaneClient("http://b", PlaneSession(node_id="n1"))
    second = PlaneClient("http://b", PlaneSession(node_id="n1"))
    assert first._run_id != second._run_id
    assert first._run_id.startswith("n1-")
    # An explicitly chosen run id is still honoured verbatim.
    pinned = PlaneClient("http://b", PlaneSession(node_id="n1"), run_id="my-run")
    assert pinned._run_id == "my-run"
