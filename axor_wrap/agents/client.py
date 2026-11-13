"""``axor-wrap hook <agent>`` — the command the agent CLI runs on each event.

Reads the event from stdin, asks the workspace sidecar (starting it if none
answers), and answers the agent. If no sidecar can be reached the call is still
judged — by a one-shot sidecar in this process, which knows only this call — so
a missing daemon never means an ungoverned call. ``AXOR_FAIL_CLOSED=1`` denies
instead when even that fails.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from axor_wrap.agents.events import HookEvent, parse_event, render_decision
from axor_wrap.agents.sidecar import Sidecar, socket_path

ENV_FAIL_CLOSED = "AXOR_FAIL_CLOSED"


def workspace_root(cwd: str) -> str:
    """The git root of ``cwd`` (one sidecar per repository), else ``cwd``."""
    try:
        out = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=cwd or None,
                             capture_output=True, text=True, timeout=2)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return os.path.realpath(cwd or os.getcwd())


def _ask(path: str, event: HookEvent, timeout: float) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout)
        conn.connect(path)
        conn.sendall((json.dumps(event.to_wire()) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf)


def _start_sidecar(root: str, path: str) -> None:
    log = Path(path).with_suffix(".log")
    # the sidecar imports THIS axor_wrap, wherever it was loaded from — it runs
    # with the workspace as cwd, where the package is usually not importable
    package_parent = str(Path(__file__).resolve().parents[2])
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (package_parent, env.get("PYTHONPATH", "")) if p)
    with open(log, "ab") as out:
        subprocess.Popen(
            [sys.executable, "-m", "axor_wrap.agents.sidecar", "--root", root,
             "--socket", path],
            stdin=subprocess.DEVNULL, stdout=out, stderr=out,
            start_new_session=True, cwd=root, env=env,
        )


def decide(event: HookEvent, *, autostart: bool = True, timeout: float = 30.0) -> dict:
    root = workspace_root(event.cwd)
    path = socket_path(root)
    try:
        return _ask(path, event, timeout)
    except (OSError, ValueError):
        pass
    if autostart:
        _start_sidecar(root, path)
        deadline = time.time() + 5.0
        while time.time() < deadline:
            time.sleep(0.1)
            try:
                return _ask(path, event, timeout)
            except (OSError, ValueError):
                continue
    try:
        # judged alone: no shared ledger, no plane — but judged
        return Sidecar(root, plane_url="").handle(event)
    except Exception as exc:  # noqa: BLE001
        if os.environ.get(ENV_FAIL_CLOSED, "") not in ("", "0", "false"):
            return {"allow": False, "reason": f"axor: governance unavailable ({exc})"}
        return {"allow": True}


def hook_main(agent: str) -> int:
    raw = sys.stdin.read()
    try:
        event = parse_event(agent, raw, dict(os.environ))
    except (ValueError, TypeError) as exc:
        print(f"axor: unreadable hook event: {exc}", file=sys.stderr)
        return 0
    out, code = render_decision(event, decide(event))
    if out:
        print(out)
    return code
