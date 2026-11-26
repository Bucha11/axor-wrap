"""`axor-wrap worker`: run, in this repository, the jobs you queue from the UI.

Started by hand in a repository, it stays in the foreground: it tells the
Control Plane it is on line (a heartbeat with the agents it can run), asks for
the jobs its owner queued for it, and runs them one at a time — a skill eval
today: the coding agent with the skill and without it, a few times each, judged
by the task's "done when" command, the report posted back to the plane.

It runs only what its owner queued. The plane offers a machine nothing else —
a job is a coding agent with permissions bypassed and a shell command, and no
one but the machine's owner may put that on it — and the worker prints each
job before it starts, so what runs in this terminal is never a surprise.

Progress goes back after every run, and every minute during one (so a long run
does not let the job's lease lapse). A cancel from the UI stops the job after
the run in progress: a run cannot be interrupted halfway.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

HEARTBEAT_S = 20.0
KEEPALIVE_S = 60.0
_TIMEOUT_S = 30.0
AGENT_BINARIES = {"claude-code": "claude", "codex": "codex"}
_INSTALL_HINT = "pip install 'axor-wrap[eval]'"


class WorkerError(RuntimeError):
    """The plane could not be reached, or refused the worker."""


class Cancelled(Exception):  # noqa: N818 - control flow, raised from the eval's callback
    """The owner cancelled the job; raised between runs."""


Http = Callable[[str, str, dict | None], dict]


def http_client(url: str, key: str) -> Http:
    """A JSON client for the plane, on the machine's saved key."""
    base = url.rstrip("/")

    def call(method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, method=method, headers={
            "Authorization": f"Bearer {key}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:  # noqa: S310 - the owner's plane
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:300]
            raise WorkerError(f"{method} {path}: HTTP {exc.code} {detail}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise WorkerError(f"{method} {path}: {exc}") from exc
        return json.loads(raw) if raw else {}

    return call


def machine_id(root: Path) -> str:
    """This repository on this host — the same id every time it starts here."""
    seed = f"{socket.gethostname()}:{root.resolve()}"
    return "m-" + hashlib.sha256(seed.encode()).hexdigest()[:16]


def agents_here() -> list[str]:
    """The coding agents on this machine's PATH."""
    return [name for name, binary in AGENT_BINARIES.items() if shutil.which(binary)]


def _say(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def run_skill_eval(job: dict, root: Path, report_trial: Callable[[Any], None],
                   plane_url: str, key: str, *,
                   on_start: Callable[[int], None] = lambda _total: None) -> str:
    """Run one skill-eval job here; the eval id of the report it posted.
    ``on_start`` gets the number of runs, counted by axor-eval itself."""
    from axor_eval.skills.__main__ import post_to_plane
    from axor_eval.skills.report import to_json
    from axor_eval.skills.runner import run_eval
    from axor_eval.skills.spec import load_spec

    # load_spec resolves the skills and the repository against the spec
    # file's folder: it is written here, read at once, and removed.
    spec_file = root / f".axor-job-{job['job_id']}.json"
    spec_file.write_text(json.dumps(job["spec"]), encoding="utf-8")
    try:
        spec = load_spec(spec_file)
    finally:
        spec_file.unlink(missing_ok=True)
    on_start(len(spec.tasks) * spec.trials * len(spec.arms))
    results = run_eval(spec, on_trial=report_trial)
    return post_to_plane(to_json(spec, results), plane_url, key)


class Worker:
    def __init__(self, http: Http, root: Path, *, plane_url: str, key: str,
                 run: Callable[..., str] = run_skill_eval,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.http = http
        self.root = root
        self.machine = machine_id(root)
        self.plane_url = plane_url
        self.key = key
        self.run = run
        self.sleep = sleep

    def heartbeat(self) -> None:
        from axor_wrap.agents.repo import repo_identity

        _, label = repo_identity(str(self.root))
        self.http("POST", "/v1/machines/heartbeat", {
            "machine_id": self.machine, "host": socket.gethostname(), "repo": label,
            "agents": agents_here()})

    def jobs(self) -> list[dict]:
        return list(self.http("GET", f"/v1/machines/{self.machine}/jobs", None).get("jobs", []))

    def _path(self, job_id: str, what: str) -> str:
        return f"/v1/machines/{self.machine}/jobs/{job_id}/{what}"

    def run_job(self, job: dict) -> str:
        """Claim and run one job; its end state."""
        job_id = job["job_id"]
        spec = job.get("spec") or {}
        _say(f"\n▶ job {job_id} from {job.get('created_by') or 'you'}: skill eval")
        _say(f"  skills: {', '.join(spec.get('skills', []))} · agent {spec.get('agent')} · "
             f"{spec.get('trials')} times each")
        for t in spec.get("tasks", []):
            _say(f"  task: {t.get('prompt')}")
            _say(f"  done when: {t.get('check')}")
        try:
            self.http("POST", self._path(job_id, "claim"), {})
        except WorkerError as exc:
            _say(f"  not taken: {exc}")
            return "skipped"

        state: dict[str, Any] = {"done": 0, "solved": 0, "total": 0, "cancel": False}
        lock = threading.Lock()

        def send(current: str = "") -> None:
            with lock:
                progress = {"done": state["done"], "total": state["total"],
                            "solved": state["solved"]}
            if current:
                progress["current"] = current
            try:
                answer = self.http("POST", self._path(job_id, "progress"), {"progress": progress})
            except WorkerError as exc:
                _say(f"  (progress not sent: {exc})")
                return
            if answer.get("cancel_requested"):
                with lock:
                    state["cancel"] = True

        def on_trial(result: Any) -> None:  # noqa: ANN401 - axor_eval TrialResult
            with lock:
                state["done"] += 1
                state["solved"] += 1 if getattr(result, "solved", False) else 0
            _say(f"  run {state['done']}/{state['total']}: "
                 f"{'solved' if getattr(result, 'solved', False) else 'not solved'}")
            send(f"{getattr(result, 'task', '')} · {getattr(result, 'arm', '')}")
            if state["cancel"]:
                raise Cancelled

        stop = threading.Event()

        def keepalive() -> None:
            while not stop.wait(KEEPALIVE_S):
                send()

        beat = threading.Thread(target=keepalive, name="axor-worker-keepalive", daemon=True)
        beat.start()
        def on_start(total: int) -> None:
            with lock:
                state["total"] = total
            send()

        end, eval_id, error = "failed", None, ""
        try:
            eval_id = self.run(job, self.root, on_trial, self.plane_url, self.key,
                               on_start=on_start)
            end = "done"
        except Cancelled:
            end, error = "cancelled", "cancelled from the Control Plane"
        except KeyboardInterrupt:
            error = "stopped on the machine (Ctrl-C)"
            raise
        except Exception as exc:  # noqa: BLE001 - any failure ends the job, said so
            error = f"{type(exc).__name__}: {exc}"
        finally:
            stop.set()
            body: dict[str, Any] = {"state": end, "error": error}
            if eval_id:
                body["eval_id"] = eval_id
            with contextlib.suppress(WorkerError):
                self.http("POST", self._path(job_id, "complete"), body)
            _say(f"■ job {job_id}: {end}" + (f" · {error}" if error else "")
                 + (f" · report {eval_id}" if eval_id else ""))
        return end

    def loop(self, *, once: bool = False) -> None:
        while True:
            self.heartbeat()
            for job in self.jobs():
                self.run_job(job)
                self.heartbeat()
            if once:
                return
            self.sleep(HEARTBEAT_S)


def main(root: Path) -> int:
    from axor_wrap import connection

    url, key = connection.plane_url(), connection.ingest_key()
    if not url or not key:
        _say("error: this machine is not connected — run `axor-wrap connect <plane url> "
             "--key <key>` first (the key from the plane's Connect page)")
        return 2
    try:
        import axor_eval.skills  # noqa: F401
    except ImportError:
        _say(f"error: running skill evals needs axor-eval — {_INSTALL_HINT}")
        return 2
    worker = Worker(http_client(url, key), root, plane_url=url, key=key)
    _say(f"axor-wrap worker · {root.resolve()} · machine {worker.machine}")
    _say(f"on {url} — queue a job from Skills → Does a skill help? · Ctrl-C to stop")
    if not agents_here():
        _say("warning: neither `claude` nor `codex` is on PATH: a job here would fail")
    try:
        worker.loop()
    except KeyboardInterrupt:
        _say("\nstopped")
        return 130
    except WorkerError as exc:
        _say(f"error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(os.getcwd())))
