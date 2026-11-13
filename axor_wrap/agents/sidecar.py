"""The workspace sidecar: what a hook invocation cannot hold on its own.

Each hook is a fresh process. Governing a SESSION needs memory across calls —
which values came from the web, what this run has done so far, the plane link
— so a hook hands its event to the sidecar for its workspace and relays the
answer. One sidecar per workspace (git root), shared by every agent working
there: one taint ledger for all of them, one governor and one recorder per
agent session, one Control-Plane node per session.

Run by the hook on first use (``python -m axor_wrap.agents.sidecar --root …``),
listening on a unix socket private to the user. Exits after
``AXOR_SIDECAR_IDLE`` seconds without an event (default 1800).
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import logging
import os
import socket
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from axor_wrap.agents import taxonomy
from axor_wrap.agents.events import HookEvent

_log = logging.getLogger("axor.wrap.agents.sidecar")

ENV_SOCKET = "AXOR_SIDECAR_SOCKET"
ENV_IDLE = "AXOR_SIDECAR_IDLE"
# off = govern and record, deny nothing (verdicts become notes to the agent)
ENV_ENFORCE = "AXOR_ENFORCE"


def socket_path(root: str) -> str:
    """Per-user, per-workspace. Under XDG_RUNTIME_DIR when there is one; the
    directory is created 0700 so no other user can reach the socket."""
    explicit = os.environ.get(ENV_SOCKET)
    if explicit:
        return explicit
    base = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
    directory = Path(base) / f"axor-{os.getuid()}"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    digest = hashlib.sha256(os.path.realpath(root).encode()).hexdigest()[:16]
    return str(directory / f"{digest}.sock")


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("output", "stdout", "content", "result", "text"):
            if isinstance(value.get(key), str):
                return value[key]
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def last_assistant_text(transcript_path: str) -> str:
    """The final assistant message in a Claude Code transcript (JSONL), for a
    Stop event that does not carry it."""
    try:
        lines = Path(transcript_path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    for line in reversed(lines):
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if entry.get("type") != "assistant":
            continue
        content = (entry.get("message") or {}).get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            text = "".join(b.get("text", "") for b in content
                           if isinstance(b, dict) and b.get("type") == "text")
            if text:
                return text
    return ""


@dataclass
class _Session:
    agent: str
    session_id: str
    node_id: str
    governor: Any
    recorder: Any
    link: Any = None
    pending: dict = field(default_factory=dict)   # tool_use_id → (decision, record)
    calls: int = 0
    last_seen: float = field(default_factory=time.time)


class Sidecar:
    """Decides hook events for one workspace. Synchronous and transport-free —
    the socket server below and the tests drive the same :meth:`handle`."""

    def __init__(
        self,
        root: str,
        *,
        enforce: bool | None = None,
        plane_url: str | None = None,
        link_factory: Callable[[str], Any] | None = None,
    ) -> None:
        from axor_core.taint.engine import TaintEngine

        self.root = root
        if enforce is None:
            enforce = os.environ.get(ENV_ENFORCE, "1") not in ("0", "off", "false")
        self.enforce = enforce
        self.plane_url = plane_url if plane_url is not None else os.environ.get("AXOR_PLANE_URL")
        self._link_factory = link_factory
        # ONE ledger for every agent in the workspace
        self.taint = TaintEngine()
        self.sessions: dict[str, _Session] = {}
        self.last_event = time.time()
        self._lock = threading.Lock()

    # ── sessions ──────────────────────────────────────────────────────────────

    def _node_id(self, event: HookEvent) -> str:
        if event.node_id:
            return event.node_id
        return f"{event.agent}-{socket.gethostname()}-{event.session_id[:8]}"

    def _session(self, event: HookEvent) -> _Session:
        key = f"{event.agent}:{event.session_id}"
        found = self.sessions.get(key)
        if found is not None:
            found.last_seen = time.time()
            return found
        from axor_core.governor import ToolCallGovernor

        from axor_wrap.observe import RunRecorder

        node_id = self._node_id(event)
        roles = dict(
            untrusted_sources=taxonomy.UNTRUSTED_SOURCES,
            egress_sinks=taxonomy.EGRESS_SINKS,
            imperative_sinks=taxonomy.IMPERATIVE_SINKS,
            benign_tools=taxonomy.BENIGN_TOOLS,
            driving_args=taxonomy.DRIVING_ARGS,
            node_id=node_id,
        )
        try:
            governor = ToolCallGovernor(taint_engine=self.taint, **roles)
        except TypeError:
            # a kernel from before shared ledgers: each session keeps its own,
            # and what one agent fetched is not seen in another
            _log.warning("axor: this axor-core cannot share a taint ledger across "
                         "agents; upgrade it for cross-agent taint")
            governor = ToolCallGovernor(**roles)
        session = _Session(event.agent, event.session_id, node_id, governor,
                           RunRecorder(node_id))
        session.link = self._open_link(node_id)
        self.sessions[key] = session
        return session

    def _open_link(self, node_id: str) -> Any:
        if self._link_factory is not None:
            return self._link_factory(node_id)
        if not self.plane_url:
            return None
        try:
            from axor_wrap.plane.link import PlaneLink

            return PlaneLink(self.plane_url, node_id)
        except Exception as exc:  # noqa: BLE001 - a plane outage must not stop the agent
            _log.warning("axor: no Control-Plane link for %s: %s", node_id, exc)
            return None

    def _ship(self, session: _Session, extra: list[dict] | None = None) -> None:
        link = session.link
        if link is None:
            return
        lines = session.recorder.pending_lines() + list(extra or [])
        if not lines:
            return
        run_id = session.recorder.run_id
        link.submit(lambda: link.connector.post_trace(lines, run_id))

    # ── events ────────────────────────────────────────────────────────────────

    def handle(self, event: HookEvent) -> dict:
        """The answer to one hook event: ``{"allow": bool, "reason": str,
        "note": str}``. Only a pre_tool answer can deny."""
        with self._lock:
            self.last_event = time.time()
            session = self._session(event)
            handler = {
                "pre_tool": self._pre_tool,
                "post_tool": self._post_tool,
                "prompt": self._prompt,
                "stop": self._stop,
                "session_end": self._session_end,
            }.get(event.kind)
            return handler(session, event) if handler else {"allow": True}

    def _deny(self, session: _Session, event: HookEvent, reason: str, gate: str) -> dict:
        record = session.recorder.begin_tool(event.tool_use_id, event.tool, event.tool_input)
        record.gate = gate
        session.recorder.end_tool(record, "", status="denied")
        self._ship(session)
        return {"allow": False, "reason": f"axor: {reason}"}

    def _pre_tool(self, session: _Session, event: HookEvent) -> dict:
        link = session.link
        if link is not None:
            posture = link.posture()
            if posture == "stopped":
                return self._deny(session, event, "this agent was stopped from the "
                                  "Control Plane", "capability")
            if posture == "paused":
                return self._deny(session, event, "this agent is paused from the "
                                  "Control Plane — wait until it is resumed", "capability")
            cap = link.budget_cap_calls()
            if cap is not None and session.calls >= cap:
                return self._deny(session, event,
                                  f"the call budget set from the Control Plane ({cap}) "
                                  "is spent", "budget")
        tool, args = taxonomy.canonical(event.agent, event.tool, event.tool_input)
        decision = session.governor.evaluate(tool, args)
        if not decision.allowed:
            from axor_core.governor import gate_of

            try:
                gate = gate_of(decision.category)
            except ValueError:
                gate = "capability"
            if self.enforce:
                return self._deny(session, event, decision.reason, gate)
            note = f"axor (observe only) would deny this call: {decision.reason}"
        else:
            note = ""
        session.calls += 1
        record = session.recorder.begin_tool(event.tool_use_id, event.tool, event.tool_input)
        record.started = True
        session.pending[event.tool_use_id or f"{event.tool}:{len(session.pending)}"] = (
            decision, record)
        self._ship(session)
        return {"allow": True, "note": note}

    def _post_tool(self, session: _Session, event: HookEvent) -> dict:
        key = event.tool_use_id
        if key not in session.pending:
            # an agent that sends no tool_use_id: the oldest open call of this tool
            key = next((k for k, (_, r) in session.pending.items() if r.tool == event.tool),
                       None)
        if key is None:
            return {"allow": True}
        decision, record = session.pending.pop(key)
        output = _text(event.tool_response)
        status = "error" if isinstance(event.tool_response, dict) and (
            event.tool_response.get("is_error") or event.tool_response.get("error")) else "ok"
        if status == "ok":
            session.governor.register_output(decision, output)
        session.recorder.end_tool(record, output, status=status)
        self._ship(session)
        return {"allow": True}

    def _prompt(self, session: _Session, event: HookEvent) -> dict:
        if session.recorder.active:
            self._finish(session, "")
        if event.prompt:
            # the user's own words: a destination they named is not tainted
            session.governor.register_task(event.prompt)
        return {"allow": True}

    def _stop(self, session: _Session, event: HookEvent) -> dict:
        answer = event.last_message or (
            last_assistant_text(event.transcript_path) if event.transcript_path else "")
        self._finish(session, answer)
        return {"allow": True}

    def _session_end(self, session: _Session, event: HookEvent) -> dict:
        self._finish(session, event.last_message)
        self.sessions.pop(f"{event.agent}:{event.session_id}", None)
        if session.link is not None:
            with contextlib.suppress(Exception):
                session.link.close()
        return {"allow": True}

    def _finish(self, session: _Session, answer: str) -> None:
        """A turn ended: its answer closes the run on the plane, and the next
        prompt starts a new one."""
        if not session.recorder.active:
            return
        claim = [{"kind": "claim", "payload": {"text": answer, "structured": False}}] \
            if answer else []
        self._ship(session, claim)
        session.pending.clear()
        session.recorder.reset()

    def close(self) -> None:
        for session in list(self.sessions.values()):
            if session.link is not None:
                with contextlib.suppress(Exception):
                    session.link.close()
        self.sessions.clear()


# ── the socket server ─────────────────────────────────────────────────────────

async def serve(root: str, path: str, *, idle: float | None = None) -> None:
    sidecar = Sidecar(root)
    idle = float(os.environ.get(ENV_IDLE, "1800")) if idle is None else idle

    async def on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await reader.readline()
            event = HookEvent.from_wire(json.loads(line))
            answer = await asyncio.to_thread(sidecar.handle, event)
        except Exception as exc:  # noqa: BLE001 - answer, never hang the agent
            _log.exception("axor sidecar: event failed")
            answer = {"allow": True, "error": f"{type(exc).__name__}: {exc}"}
        writer.write((json.dumps(answer) + "\n").encode())
        with contextlib.suppress(Exception):
            await writer.drain()
            writer.close()

    if os.path.exists(path):
        if _alive(path):
            return  # another sidecar already serves this workspace
        os.unlink(path)
    server = await asyncio.start_unix_server(on_client, path=path)
    os.chmod(path, 0o600)
    async with server:
        while time.time() - sidecar.last_event < idle:
            await asyncio.sleep(min(5.0, idle))
    sidecar.close()
    with contextlib.suppress(OSError):
        os.unlink(path)


def _alive(path: str) -> bool:
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(0.5)
    try:
        probe.connect(path)
        return True
    except OSError:
        return False
    finally:
        probe.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="axor-wrap-sidecar")
    parser.add_argument("--root", required=True)
    parser.add_argument("--socket", default=None)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    asyncio.run(serve(args.root, args.socket or socket_path(args.root)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
