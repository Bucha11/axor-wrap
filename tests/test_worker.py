"""`axor-wrap worker` against a fake plane: a queued job is claimed, run,
reported after every run, and finished — and a cancel stops it between runs."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from axor_wrap import worker as w

JOB = {"job_id": "job-1", "created_by": "ada@acme.io", "kind": "skill_eval",
       "spec": {"skills": ["./skills/changelog"], "agent": "claude-code", "trials": 2,
                "tasks": [{"name": "t", "prompt": "fix it", "check": "true"}]}}


@dataclass
class Trial:
    solved: bool
    task: str = "t"
    arm: str = "all"


class FakePlane:
    def __init__(self, jobs: list[dict] | None = None, *, claim_ok: bool = True,
                 cancel_after: int | None = None) -> None:
        self.queue = list(jobs or [])
        self.claim_ok = claim_ok
        self.cancel_after = cancel_after
        self.calls: list[tuple[str, str, dict | None]] = []
        self.progress: list[dict] = []
        self.completed: list[dict] = []

    def __call__(self, method: str, path: str, body: dict | None = None) -> dict:
        self.calls.append((method, path, body))
        if path.endswith("/heartbeat"):
            return {}
        if path.endswith("/jobs") and method == "GET":
            jobs, self.queue = self.queue, []
            return {"jobs": jobs}
        if path.endswith("/claim"):
            if not self.claim_ok:
                raise w.WorkerError("HTTP 409 this job is not waiting for this machine")
            return {"state": "running"}
        if path.endswith("/progress"):
            self.progress.append(body["progress"])
            done = body["progress"]["done"]
            return {"cancel_requested": self.cancel_after is not None and done >= self.cancel_after}
        if path.endswith("/complete"):
            self.completed.append(body)
            return {}
        raise AssertionError(path)


def _worker(plane: FakePlane, run, tmp_path: Path) -> w.Worker:  # noqa: ANN001
    worker = w.Worker(plane, tmp_path, plane_url="https://plane.test", key="k", run=run,
                      sleep=lambda _s: None)
    worker.heartbeat = lambda: None   # repo_identity shells out to git
    return worker


def test_a_job_is_claimed_run_reported_and_finished(tmp_path: Path) -> None:
    plane = FakePlane([JOB])

    def run(job, root, on_trial, url, key, *, on_start):  # noqa: ANN001, ANN202
        assert (job["job_id"], root, url, key) == ("job-1", tmp_path, "https://plane.test", "k")
        on_start(4)
        for solved in (True, False, True, True):
            on_trial(Trial(solved))
        return "se-123"

    _worker(plane, run, tmp_path).loop(once=True)
    assert plane.progress[0] == {"done": 0, "total": 4, "solved": 0}
    assert plane.progress[-1]["done"] == 4 and plane.progress[-1]["solved"] == 3
    assert plane.completed == [{"state": "done", "error": "", "eval_id": "se-123"}]
    claim = [p for _, p, _ in plane.calls if p.endswith("/claim")]
    assert claim == [f"/v1/machines/{w.machine_id(tmp_path)}/jobs/job-1/claim"]


def test_a_cancel_from_the_ui_stops_it_between_runs(tmp_path: Path) -> None:
    plane = FakePlane([JOB], cancel_after=2)
    ran = []

    def run(job, root, on_trial, url, key, *, on_start):  # noqa: ANN001, ANN202
        on_start(4)
        for _ in range(4):
            on_trial(Trial(True))
            ran.append(1)
        return "se-never"

    _worker(plane, run, tmp_path).loop(once=True)
    assert len(ran) == 1          # the second run's report carried the cancel
    assert plane.completed == [{"state": "cancelled", "error": "cancelled from the Control Plane"}]


def test_a_failing_run_ends_the_job_failed_and_says_why(tmp_path: Path) -> None:
    plane = FakePlane([JOB])

    def run(job, root, on_trial, url, key, *, on_start):  # noqa: ANN001, ANN202
        raise FileNotFoundError("claude: not found")

    _worker(plane, run, tmp_path).loop(once=True)
    (done,) = plane.completed
    assert done["state"] == "failed" and "claude: not found" in done["error"]


def test_a_job_another_worker_took_is_left_alone(tmp_path: Path) -> None:
    plane = FakePlane([JOB], claim_ok=False)
    ran = []
    _worker(plane, lambda *a, **k: ran.append(1), tmp_path).loop(once=True)
    assert ran == [] and plane.completed == []


def test_the_machine_id_is_this_repository_on_this_host(tmp_path: Path) -> None:
    assert w.machine_id(tmp_path) == w.machine_id(tmp_path)
    assert w.machine_id(tmp_path) != w.machine_id(tmp_path / "other")
    assert w.machine_id(tmp_path).startswith("m-")


def test_an_unconnected_machine_is_told_how_to_connect(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("AXOR_PLANE_URL", raising=False)
    monkeypatch.delenv("AXOR_INGEST_KEY", raising=False)
    assert w.main(tmp_path) == 2
    assert "axor-wrap connect" in capsys.readouterr().err
