"""A session past the free plan is kept by the plane but not shown or operated:
the developer hears it once, in their own agent — protected here regardless."""
from __future__ import annotations

import json
import tempfile
from types import SimpleNamespace

from axor_wrap.agents.events import parse_event, render_decision
from axor_wrap.agents.sidecar import Sidecar


class _Link:
    def __init__(self, answer: dict | None) -> None:
        self.connector = SimpleNamespace(profile_answer=answer)

    def __getattr__(self, name: str):  # noqa: ANN204 - a link that does nothing else
        return lambda *a, **k: None


def _run(answer: dict | None) -> list[str]:
    root = tempfile.mkdtemp()
    car = Sidecar(root, enforce=True, link_factory=lambda node: _Link(answer))
    said = []
    for raw in ({"hook_event_name": "SessionStart"},
                {"hook_event_name": "UserPromptSubmit", "prompt": "tidy app.py"},
                {"hook_event_name": "UserPromptSubmit", "prompt": "and the tests"}):
        ev = parse_event("claude-code", {"session_id": "s", "cwd": root, **raw})
        out, code = render_decision(ev, car.handle(ev))
        assert code == 0
        msg = (json.loads(out) if out else {}).get("systemMessage")
        if msg:
            said.append(msg)
    return said


def test_a_locked_session_is_told_once() -> None:
    said = _run({"locked": ["developer"], "detail": "a second developer in this workspace"})
    assert len(said) == 1
    assert "protected on this machine" in said[0] and "second developer" in said[0]


def test_a_session_the_plan_shows_hears_nothing() -> None:
    assert _run({"locked": []}) == []
    assert _run(None) == []          # an older plane says nothing either
