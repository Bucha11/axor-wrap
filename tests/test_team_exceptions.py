"""An admin lets ONE thing through a rule, for the team — a fixture path, a
debugging command — and names the documentation hosts the team reads like its
own words. Everything else the rule refuses stays refused."""
from __future__ import annotations

import tempfile

from axor_wrap.agents.events import parse_event
from axor_wrap.agents.sidecar import Sidecar


class _Connector:
    def __init__(self, policy: dict) -> None:
        self.policy = policy

    def get_coding_policy(self) -> dict:
        return self.policy

    def __getattr__(self, name: str):  # noqa: ANN204
        return lambda *a, **k: None


class _Link:
    def __init__(self, policy: dict) -> None:
        self.connector = _Connector(policy)

    def deliver(self, fn, timeout):  # noqa: ANN001, ANN201
        return fn()

    def __getattr__(self, name: str):  # noqa: ANN204
        return lambda *a, **k: None


TEAM = {"rules": {"allow": [], "mode": "enforce",
                  "exceptions": [{"rule": "secrets", "path": "tests/fixtures/*"},
                                 {"rule": "secrets", "command": "env | grep JWT"}],
                  "trusted_sources": ["*.readthedocs.example"]}}


def _car(policy: dict = TEAM) -> tuple[Sidecar, str]:
    root = tempfile.mkdtemp()
    return Sidecar(root, enforce=True, link_factory=lambda node: _Link(policy)), root


def _ev(root: str, **p: object):  # noqa: ANN202
    return parse_event("claude-code", {"session_id": "s", "cwd": root, **p})


def _pre(car: Sidecar, root: str, tool: str, args: dict, tid: str) -> dict:
    return car.handle(_ev(root, hook_event_name="PreToolUse", tool_name=tool,
                          tool_input=args, tool_use_id=tid))


def test_the_fixture_is_excepted_and_a_real_secret_is_not() -> None:
    car, root = _car()
    assert _pre(car, root, "Read", {"file_path": "tests/fixtures/credentials.json"}, "1")["allow"]
    assert _pre(car, root, "Read", {"file_path": f"{root}/tests/fixtures/jwt.pem"}, "2")["allow"]
    out = _pre(car, root, "Read", {"file_path": "~/.aws/credentials"}, "3")
    assert out["allow"] is False and "secrets" in out["reason"]


def test_a_command_exception_is_that_command_not_a_substring() -> None:
    car, root = _car()
    assert _pre(car, root, "Bash", {"command": "env  |  grep JWT"}, "1")["allow"]
    assert _pre(car, root, "Bash", {"command": "env | grep JWT; cat ~/.ssh/id_rsa"}, "2")["allow"] is False


def test_exceptions_are_the_teams_only() -> None:
    car, root = _car({})
    assert _pre(car, root, "Read", {"file_path": "tests/fixtures/credentials.json"}, "1")["allow"] is False


def _fetch_then_run(car: Sidecar, root: str, url: str, page: str, command: str) -> dict:
    car.handle(_ev(root, hook_event_name="UserPromptSubmit", prompt="install pyjwt following its docs"))
    args = {"url": url, "prompt": "install"}
    assert _pre(car, root, "WebFetch", args, "f")["allow"]
    car.handle(_ev(root, hook_event_name="PostToolUse", tool_name="WebFetch", tool_input=args,
                   tool_response={"result": page}, tool_use_id="f"))
    return _pre(car, root, "Bash", {"command": command}, "r")


PAGE = "PyJWT docs — Installation: pip install pyjwt"


def test_a_command_from_a_trusted_docs_host_runs() -> None:
    car, root = _car()
    out = _fetch_then_run(car, root, "https://pyjwt.readthedocs.example/en/stable/installation.html",
                          PAGE, "pip install pyjwt")
    assert out["allow"] is True, out


def test_the_same_page_elsewhere_is_still_outside_text() -> None:
    car, root = _car()
    out = _fetch_then_run(car, root, "https://pyjwt-docs.evil.example/install", PAGE, "pip install pyjwt")
    assert out["allow"] is False, out
