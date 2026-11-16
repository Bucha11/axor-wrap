"""A coding agent's checks — tests, a build, a linter, a type checker — and
what each found, read in the sidecar where the whole output is; and the failed
call that Claude Code reports as PostToolUseFailure, which used to be lost."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from axor_wrap.agents import parse_event
from axor_wrap.agents.checks import check_kind, check_of
from axor_wrap.agents.install import install
from axor_wrap.agents.sidecar import Sidecar


@pytest.mark.parametrize(("command", "kind"), [
    ("pytest -q tests/", "tests"), ("python -m pytest", "tests"), ("npm test", "tests"),
    ("pnpm run test -- --watch=false", "tests"), ("go test ./...", "tests"),
    ("cargo test", "tests"), ("npx tsc --noEmit -p .", "typecheck"), ("mypy src", "typecheck"),
    ("ruff check .", "lint"), ("npx eslint src", "lint"), ("npm run build", "build"),
    ("cargo build --release", "build"), ("ls -la", None), ("git status", None),
])
def test_which_commands_are_checks(command: str, kind: str | None) -> None:
    assert check_kind(command) == kind


def test_what_a_check_found() -> None:
    ok = check_of("pytest -q", "....\n===== 12 passed in 0.4s =====", failed=False)
    assert ok == {"kind": "tests", "passed": True, "summary": "===== 12 passed in 0.4s =====",
                  "command": "pytest -q"}
    bad = check_of("pytest -q", "..F.\n=== 1 failed, 11 passed in 0.5s ===", failed=False)
    assert bad["passed"] is False and "1 failed" in bad["summary"]
    assert check_of("npm test", "Tests:  2 failed, 30 passed, 32 total", failed=False)["passed"] is False
    assert check_of("npx tsc --noEmit", "src/a.ts(3,1): error TS2322: Type 'x'", failed=False)["passed"] is False
    assert check_of("ruff check .", "Found 3 errors.", failed=False)["passed"] is False
    assert check_of("go test ./...", "--- FAIL: TestX (0.00s)\nFAIL", failed=False)["passed"] is False
    assert check_of("ruff check .", "All checks passed!", failed=False)["passed"] is True
    # the runtime said it failed; the output says nothing either way
    exited = check_of("npm test", '{"error": "Exit code 1"}', failed=True)
    assert exited["passed"] is False and "Exit code 1" in exited["summary"]
    assert check_of("pytest", "", failed=False, interrupted=True)["summary"] == "timed out"
    assert check_of("ls", "x", failed=True) is None


def _ev(name: str, **fields: object) -> dict:
    return {"hook_event_name": name, "session_id": "s1", "cwd": "/repo", **fields}


def test_post_tool_use_failure_is_a_failed_call() -> None:
    e = parse_event("claude-code", _ev(
        "PostToolUseFailure", tool_name="Bash", tool_input={"command": "pytest"},
        tool_use_id="t1", error="Exit code 1\n=== 2 failed ===", is_interrupt=False))
    assert e.kind == "post_tool"
    assert e.tool_response == {"error": "Exit code 1\n=== 2 failed ===", "is_error": True,
                               "interrupted": False}


class _Link:
    def __init__(self) -> None:
        self.shipped: list = []
        outer = self

        class _Conn:
            async def post_trace(self, lines: list, run_id: str) -> None:
                outer.shipped.extend(lines)

        self.connector = _Conn()

    def posture(self) -> str:
        return "running"

    def budget_cap_calls(self) -> None:
        return None

    def submit(self, fn) -> None:  # noqa: ANN001
        import asyncio

        asyncio.run(fn())

    def close(self) -> None:
        pass


def test_a_failing_test_run_ships_as_a_failed_check() -> None:
    link = _Link()
    car = Sidecar("/repo", enforce=True, link_factory=lambda n: link)
    car.handle(parse_event("claude-code", _ev(
        "PreToolUse", tool_name="Bash", tool_input={"command": "pytest -q"}, tool_use_id="t1")))
    car.handle(parse_event("claude-code", _ev(
        "PostToolUseFailure", tool_name="Bash", tool_input={"command": "pytest -q"},
        tool_use_id="t1", error="Exit code 1\n=== 2 failed, 10 passed ===")))
    car.handle(parse_event("claude-code", _ev("Stop", last_assistant_message="All tests pass.")))
    lines = [ln for ln in link.shipped if isinstance(ln, dict)]
    result = next(ln for ln in lines if ln.get("kind") == "tool_result")
    assert result["payload"]["status"] == "error"
    assert result["payload"]["check"]["passed"] is False
    assert "2 failed" in result["payload"]["check"]["summary"]
    assert any(ln.get("kind") == "claim" for ln in lines)


def test_claude_code_is_given_the_failure_event_and_codex_is_not(tmp_path: Path) -> None:
    claude = json.loads(install("claude-code", tmp_path).read_text())["hooks"]
    assert "PostToolUseFailure" in claude and claude["PostToolUseFailure"][0]["matcher"] == "*"
    codex = json.loads(install("codex", tmp_path).read_text())["hooks"]
    assert "PostToolUseFailure" not in codex
