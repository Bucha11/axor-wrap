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


def test_past_the_seat_limit_the_admin_raises_it() -> None:
    said = _run({"locked": ["seat_cap"],
                 "detail": "past the workspace's seat limit this month"})
    assert len(said) == 1 and "can raise the seat limit" in said[0]
    assert "Coding plan" not in said[0]


def test_a_session_the_plan_shows_hears_nothing() -> None:
    assert _run({"locked": []}) == []
    assert _run(None) == []          # an older plane says nothing either


def test_the_first_request_names_the_session() -> None:
    import asyncio

    titles: list[str] = []

    class _Conn:
        profile_answer = None

        async def post_title(self, title: str) -> bool:
            titles.append(title)
            return True

    class _TitleLink:
        connector = _Conn()

        def submit(self, fn):  # noqa: ANN001, ANN201
            asyncio.run(fn())

        def __getattr__(self, name: str):  # noqa: ANN204
            return lambda *a, **k: None

    root = tempfile.mkdtemp()
    car = Sidecar(root, enforce=True, link_factory=lambda node: _TitleLink())
    for text in ("add a 10% discount\n for orders over $100", "and run the tests"):
        car.handle(parse_event("claude-code", {"session_id": "s", "cwd": root,
                                               "hook_event_name": "UserPromptSubmit", "prompt": text}))
    assert titles == ["add a 10% discount for orders over $100"]


def test_the_real_connector_carries_title_and_profile_answer() -> None:
    """The sidecar talks to a PlaneConnector, which delegates to PlaneClient:
    both what it sends (a title) and what it reads (the profile's answer) must
    be on the connector, not only on the client behind it."""
    from axor_wrap.connect import PlaneConnector

    assert callable(getattr(PlaneConnector, "post_title", None))
    assert "profile_answer" in dir(PlaneConnector)
