from __future__ import annotations

import json
import re
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from axor_wrap.connect import LabRuntimeConnector
from axor_wrap.errors import ConnectorError

_CLAIM_RE = re.compile(r"^/runtime/jobs/([A-Za-z0-9_]+)/claim$")
_EVENTS_RE = re.compile(r"^/runtime/jobs/([A-Za-z0-9_]+)/trials/([A-Za-z0-9_.:-]+)/events$")
_DONE_RE = re.compile(r"^/runtime/jobs/([A-Za-z0-9_]+)/trials/([A-Za-z0-9_.:-]+)/complete$")

CONTROL_TOKEN = "ctl-secret"
INGEST_KEY = "ingest-key-123"


class _StubState:
    """Replays the runtime_jobs handshake: connect → poll → claim → events → complete."""

    def __init__(self) -> None:
        self.connected: list[dict] = []
        self.events: list[tuple[str, str, list]] = []
        self.completed: list[tuple[str, str, dict | None, str]] = []
        self.claimed: list[str] = []


class _StubHandler(BaseHTTPRequestHandler):
    state: _StubState

    def log_message(self, *_args: object) -> None:
        return

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _bearer(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        return auth[7:] if auth.startswith("Bearer ") else None

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        return json.loads(self.rfile.read(length)) if length else {}

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/runtime/jobs":
            if self._bearer() != INGEST_KEY:
                self._send(401, {"error": "a valid runtime ingest_key is required"})
                return
            self._send(200, {"jobs": [{"job_id": "run_0001", "state": "waiting_for_runtime",
                                       "planned_trials": ["s:c:0"]}]})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/runtimes/connect":
            if self._bearer() != CONTROL_TOKEN:
                self._send(401, {"error": "control token required"})
                return
            self.state.connected.append(self._body())
            self._send(201, {"runtime_ref": "rt_0001", "ingest_key": INGEST_KEY})
            return
        if self._bearer() != INGEST_KEY:
            self._send(401, {"error": "a valid runtime ingest_key is required"})
            return
        m = _CLAIM_RE.match(self.path)
        if m:
            self.state.claimed.append(m.group(1))
            self._send(200, {"run_id": m.group(1), "assignment": {"experiment": "e1"},
                             "planned_trials": ["s:c:0"]})
            return
        m = _EVENTS_RE.match(self.path)
        if m:
            events = self._body().get("events", [])
            self.state.events.append((m.group(1), m.group(2), events))
            self._send(200, {"trial_id": m.group(2), "events": len(events), "attempt": 1})
            return
        m = _DONE_RE.match(self.path)
        if m:
            body = self._body()
            self.state.completed.append((m.group(1), m.group(2), body.get("trace"),
                                         str(body.get("status", "completed"))))
            self._send(200, {"trial_id": m.group(2), "status": body.get("status", "completed"),
                             "run_state": "completed", "attempt": 1, "superseded": 0})
            return
        self._send(404, {"error": "not found"})


class ConnectTest(unittest.TestCase):
    server: ThreadingHTTPServer

    @classmethod
    def setUpClass(cls) -> None:
        cls.state = _StubState()
        handler = type("Handler", (_StubHandler,), {"state": cls.state})
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def connector(self) -> LabRuntimeConnector:
        return LabRuntimeConnector(self.base_url, control_token=CONTROL_TOKEN)

    def test_full_handshake(self) -> None:
        connector = self.connector()
        payload = connector.connect(runtime_label="claude-fable-5", agent_ref="agent@1")
        self.assertEqual(payload["runtime_ref"], "rt_0001")
        self.assertEqual(connector.runtime_ref, "rt_0001")
        self.assertEqual(connector.ingest_key, INGEST_KEY)
        self.assertIn({"runtime_label": "claude-fable-5", "agent_ref": "agent@1"}, self.state.connected)

        jobs = connector.poll_jobs()
        self.assertEqual(jobs[0]["job_id"], "run_0001")

        claim = connector.claim("run_0001")
        self.assertEqual(claim["assignment"], {"experiment": "e1"})
        self.assertIn("run_0001", self.state.claimed)

        posted = connector.post_events("run_0001", "s:c:0", [{"type": "gate", "verdict": "ALLOW"}])
        self.assertEqual(posted["events"], 1)
        self.assertEqual(self.state.events[-1][:2], ("run_0001", "s:c:0"))

        done = connector.complete_trial("run_0001", "s:c:0", {"trial": {"id": "s:c:0"}})
        self.assertEqual(done["status"], "completed")
        self.assertEqual(self.state.completed[-1],
                         ("run_0001", "s:c:0", {"trial": {"id": "s:c:0"}}, "completed"))

    def test_connect_requires_control_token(self) -> None:
        connector = LabRuntimeConnector(self.base_url, control_token="wrong")
        with self.assertRaises(ConnectorError) as ctx:
            connector.connect(runtime_label="m")
        self.assertEqual(ctx.exception.status, 401)

    def test_runtime_calls_before_connect_fail_honestly(self) -> None:
        connector = self.connector()
        with self.assertRaises(ConnectorError) as ctx:
            connector.poll_jobs()
        self.assertIn("connect() first", ctx.exception.message)

    def test_bad_ingest_key_is_a_401(self) -> None:
        connector = self.connector()
        connector.ingest_key = "wrong"
        with self.assertRaises(ConnectorError) as ctx:
            connector.poll_jobs()
        self.assertEqual(ctx.exception.status, 401)

    def test_unreachable_server_is_transport_error(self) -> None:
        connector = LabRuntimeConnector("http://127.0.0.1:1", control_token="t", timeout=0.5)
        with self.assertRaises(ConnectorError) as ctx:
            connector.connect(runtime_label="m")
        self.assertEqual(ctx.exception.status, 0)


if __name__ == "__main__":
    unittest.main()
