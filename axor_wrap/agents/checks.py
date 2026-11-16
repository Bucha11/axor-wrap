"""What a coding agent's check command found — tests, a build, a linter, a
type checker — read here, where the whole output is, and shipped as
``tool_result.payload.check = {kind, passed, summary, command}``.

The plane's audit (axor-eval ``audit.check_audit``, the same table of
commands) then holds the agent's last word against the last result of each
kind: "all tests pass" after a failing run is the coding agent's usual lie.

Read conservatively. ``passed`` is False only on a clear failure: the call
failed (a non-zero exit reaches Claude Code as PostToolUseFailure, "Exit code
N"), it timed out or was interrupted, or the output carries a runner's own
failure line ("2 failed", "FAIL", "error TS2322", "Found 3 errors"). Output
that says nothing either way on a call that did not fail reads as passed.
"""
from __future__ import annotations

import re

_KINDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("tests", re.compile(
        r"\b(pytest|py\.test|python\d?(\.\d+)? -m (pytest|unittest)|tox|nox|"
        r"(npm|pnpm|yarn|bun)( run)? test|jest|vitest|mocha|go test|cargo (test|nextest)|"
        r"mvn( -\S+)* (test|verify)|gradle(w)? test|\./gradlew test|make (test|check)|"
        r"rspec|phpunit|dotnet test|deno test|swift test)\b")),
    ("typecheck", re.compile(r"\b(mypy|pyright|tsc|vue-tsc|flow check|(npm|pnpm|yarn) run (typecheck|tsc))\b")),
    ("lint", re.compile(r"\b(ruff( check)?|flake8|pylint|eslint|biome (check|lint)|golangci-lint|"
                        r"clippy|rubocop|(npm|pnpm|yarn) run lint)\b")),
    ("build", re.compile(r"\b((npm|pnpm|yarn|bun) run build|cargo build|go build|mvn( -\S+)* package|"
                         r"gradle(w)? build|make( build)?$|docker build|vite build|next build)\b")),
)

# a runner's own words for "it failed", and the line worth showing
_FAILED = re.compile(
    r"(^|\n)\s*(=+ .*\b\d+ (failed|errors?)\b.*=+|FAILED\b.*|FAIL\b.*|"
    r"Tests?:\s+\d+ failed.*|test result: FAILED.*|\d+ (failed|failing)\b.*|"
    r"error(\[E\d+\])?:.*|.*error TS\d+:.*|Found \d+ errors?.*|✖ \d+ problems?.*|"
    r"npm ERR!.*|ERR_PNPM.*|Exit code [1-9]\d*.*|.*\bTraceback \(most recent call last\).*)",
)
_PASSED_LINE = re.compile(
    r"(^|\n)\s*(=+ .*\b\d+ passed\b.*=+|Tests?:\s+\d+ passed.*|test result: ok.*|ok\s+\S+.*|"
    r"All checks passed!?|Success: no issues found.*|PASS\b.*|\d+ passing\b.*)",
)


def check_kind(command: str) -> str | None:
    for kind, pattern in _KINDS:
        if pattern.search(command):
            return kind
    return None


def _last(pattern: re.Pattern[str], text: str) -> str:
    found = [m.group(0).strip() for m in pattern.finditer(text)]
    return found[-1][:160] if found else ""


def check_of(command: str, output: str, *, failed: bool, interrupted: bool = False) -> dict | None:
    """The check this command ran and what it found, or None when it is not a
    check. ``failed``: the agent's runtime reported the call as failed."""
    kind = check_kind(command)
    if kind is None:
        return None
    fail_line = _last(_FAILED, output)
    timed_out = interrupted or bool(re.search(r"\btimed? ?out\b|\bTimeout\b", output[-400:]))
    passed = not (failed or timed_out or fail_line)
    if passed:
        summary = _last(_PASSED_LINE, output)
    elif fail_line:
        summary = fail_line
    elif timed_out:
        summary = "timed out"
    else:  # the runtime said it failed: its own words, e.g. "Exit code 1"
        code = re.search(r"Exit code \d+", output)
        summary = code.group(0) if code else "failed"
    return {"kind": kind, "passed": passed, "summary": summary, "command": command[:200]}
