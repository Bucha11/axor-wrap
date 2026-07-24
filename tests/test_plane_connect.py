"""PlaneConnector against a real (stdlib) plane-backend stub.

The stub replays the minimum of the plane protocol the connector actually
speaks: it accepts heartbeat telemetry (``POST /v1/plane/{node}/telemetry``) and
serves desired state over SSE (``GET /v1/plane/{node}/desired``) — a snapshot on
subscribe, then any pushed deltas. Nothing here is mocked at the protocol
boundary: the connector's own ``PlaneClient``/``PlaneSession`` (``axor_wrap.plane``)
consume the real SSE bytes and apply the delta, so ``session.paused`` flipping is
genuine plane code doing the work.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import queue
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Gate on the plane extra without importing anything: find_spec is inert, so the
# check itself never drags the transport (or the kernel) into a wrap-only run.
HAS_PLANE = all(
    importlib.util.find_spec(mod) is not None
    for mod in ("httpx", "cryptography", "axor_core")
)

from axor_wrap.connect import PlaneConnector
from axor_wrap.errors import AdmissionHeld
from axor_wrap.runtime import WrappedToolset

NODE_ID = "wrapped-node-1"


class _PlaneStub:
    """Backend-side state: collected telemetry + per-node desired-delta queues."""

    def __init__(self) -> None:
        self.telemetry: list[dict] = []
        self.probe_reports: list[dict] = []
        self.telemetry_seen = threading.Event()
        self.subscribed = threading.Event()
        self.shutdown = threading.Event()
        self._queues: dict[str, queue.Queue[dict]] = {}
        self._lock = threading.Lock()

    def queue_for(self, node_id: str) -> queue.Queue[dict]:
        with self._lock:
            return self._queues.setdefault(node_id, queue.Queue())

    def publish_delta(self, node_id: str, version: int, delta: dict) -> None:
        self.queue_for(node_id).put({
            "version": version, "delta": delta,
            "operator": "", "timestamp": "", "sig": "",
        })


def _handler(stub: _PlaneStub) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return

        def _read_body(self) -> dict:
            length = int(self.headers.get("Content-Length", 0) or 0)
            return json.loads(self.rfile.read(length)) if length else {}

        def _json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            parts = self.path.strip("/").split("/")
            # /v1/plane/{node}/telemetry  or  /v1/plane/{node}/consumed
            if len(parts) == 4 and parts[:2] == ["v1", "plane"]:
                body = self._read_body()
                if parts[3] == "telemetry":
                    stub.telemetry.append(body)
                    stub.telemetry_seen.set()
                if parts[3] == "probe-report":
                    stub.probe_reports.append(body)
                    self._json(201, {"stored": True, "id": len(stub.probe_reports)})
                    return
                self._json(200, {"ok": True})
                return
            self._json(404, {"error": "not found"})

        def do_GET(self) -> None:  # noqa: N802
            parts = self.path.strip("/").split("/")
            if len(parts) == 4 and parts[:2] == ["v1", "plane"] and parts[3] == "desired":
                self._stream_desired(parts[2])
                return
            self._json(404, {"error": "not found"})

        def _sse(self, event: str, data: dict) -> None:
            self.wfile.write(
                f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()
            )
            self.wfile.flush()

        def _stream_desired(self, node_id: str) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            q = stub.queue_for(node_id)
            try:
                self._sse("snapshot", {"version": 1, "state": {}})
                stub.subscribed.set()
                while not stub.shutdown.is_set():
                    try:
                        item = q.get(timeout=0.1)
                    except queue.Empty:
                        continue
                    self._sse("delta", item)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return  # client wound down its subscription — expected

    return _Handler


class _AllowGovernor:
    """A stand-in governor so the toolset needs no axor-core install: it allows
    every call, letting the test isolate the plane admission gate."""

    class _Decision:
        allowed = True
        reason = ""
        category = "allow"

    def evaluate(self, name: str, args: dict[str, object]) -> _AllowGovernor._Decision:
        return self._Decision()

    def register_output(self, decision: object, output: object) -> None:
        return None


@unittest.skipUnless(HAS_PLANE, "requires axor-wrap[plane] (axor-core + httpx + cryptography)")
class PlaneConnectorTest(unittest.TestCase):
    server: ThreadingHTTPServer

    def setUp(self) -> None:
        self.stub = _PlaneStub()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(self.stub))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.stub.shutdown.set()
        self.server.shutdown()
        self.server.server_close()

    @staticmethod
    async def _until(predicate, timeout: float = 5.0) -> bool:  # noqa: ANN001
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            if predicate():
                return True
            await asyncio.sleep(0.02)
        return False

    def test_node_registers_and_applies_pause_delta(self) -> None:
        asyncio.run(self._body())

    async def _body(self) -> None:
        connector = PlaneConnector(
            self.base_url, NODE_ID, heartbeat_period=0.1, test_bench=True,
        )
        connector.connect()

        # A wrapped toolset bound to this node — its calls poll the node posture.
        toolset = WrappedToolset(
            {"noop": lambda **_: "ok"},
            manifests=[],
            governor=_AllowGovernor(),
        )
        connector.gate(toolset)

        run_task = asyncio.create_task(connector.run())
        try:
            # (a) node is live: heartbeat telemetry landed on the backend.
            self.assertTrue(
                await self._until(lambda: self.stub.telemetry_seen.is_set()),
                "connector never sent a heartbeat",
            )
            kinds = [
                e["kind"]
                for batch in self.stub.telemetry
                for e in batch.get("events", [])
            ]
            self.assertIn("heartbeat", kinds)

            # subscription established → snapshot consumed, posture is NORMAL and
            # the bound toolset admits calls.
            self.assertTrue(await self._until(lambda: self.stub.subscribed.is_set()))
            self.assertEqual(connector.level(), "NORMAL")
            self.assertTrue(connector.admit())
            self.assertEqual(toolset.call("noop", {}), "ok")

            # (b) operator pushes a real desired-delta: pause the node.
            self.stub.publish_delta(NODE_ID, version=2, delta={"paused": True})

            applied = await self._until(lambda: connector.session.paused)
            self.assertTrue(applied, "pause delta was never applied to the session")

            # The delta reached the node by real plane code — observable posture,
            # level, admission, and the wrapped runtime's actual tool execution.
            self.assertTrue(connector.session.paused)
            self.assertEqual(connector.level(), "CAUTIOUS")
            self.assertFalse(connector.admit())
            with self.assertRaises(AdmissionHeld):
                toolset.call("noop", {})
        finally:
            connector.stop()
            await asyncio.wait_for(run_task, timeout=5.0)

    def test_stop_delta_restricts_and_holds(self) -> None:
        asyncio.run(self._stop_body())

    async def _stop_body(self) -> None:
        connector = PlaneConnector(self.base_url, NODE_ID, heartbeat_period=0.1)
        connector.connect()
        run_task = asyncio.create_task(connector.run())
        try:
            self.assertTrue(await self._until(lambda: self.stub.subscribed.is_set()))
            self.stub.publish_delta(NODE_ID, version=5, delta={"stopped": True})
            stopped = await self._until(lambda: connector.session.stopped)
            self.assertTrue(stopped, "stop delta was never applied")
            self.assertEqual(connector.level(), "RESTRICTED")
            self.assertFalse(connector.admit())
        finally:
            connector.stop()
            await asyncio.wait_for(run_task, timeout=5.0)

    def test_run_honours_ttl(self) -> None:
        asyncio.run(self._ttl_body())

    async def _ttl_body(self) -> None:
        connector = PlaneConnector(self.base_url, NODE_ID, heartbeat_period=0.05)
        connector.connect()
        # ttl returns on its own without an explicit stop().
        await asyncio.wait_for(connector.run(ttl=0.3), timeout=5.0)
        self.assertTrue(self.stub.telemetry_seen.is_set())


    def test_health_check_reaches_the_plane(self) -> None:
        asyncio.run(self._health_body())

    async def _health_body(self) -> None:
        # The payload shape is axor-probe's health_payload output, hand-built:
        # axor-wrap transports it without importing axor-probe.
        payload = {
            "session_id": "s1", "agent_id": NODE_ID, "model": "m",
            "probe_library_version": "1.0.0",
            "overall_verdict": "DRIFT_DETECTED",
            "families": [
                {"family": "data_disclosure", "state": "escaped",
                 "escapes": 1, "probes": 3},
            ],
            "probes_sent": 3, "probes_invalid": 0, "probes_triangulated": 0,
            "structural_failures": 0, "escape_count": 1, "escape_rate": 0.33,
            "escape_rate_ci": [0.0, 0.9],
            "calibration_status": "UNCALIBRATED",
            "max_drift_score_uncalibrated": 0.6,
        }
        connector = PlaneConnector(self.base_url, NODE_ID)
        accepted = await connector.post_health_check(payload)
        self.assertTrue(accepted)
        # Delivered verbatim over real HTTP — the node reports, the plane stores.
        self.assertEqual(self.stub.probe_reports, [payload])


class PlaneConnectorConnectionErrorsTest(unittest.TestCase):
    def test_level_before_connect_is_honest(self) -> None:
        connector = PlaneConnector("http://127.0.0.1:1", NODE_ID)
        from axor_wrap.errors import ConnectorError

        with self.assertRaises(ConnectorError):
            connector.level()


if __name__ == "__main__":
    unittest.main()
