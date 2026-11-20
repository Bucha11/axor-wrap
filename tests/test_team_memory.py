"""The team's memory: which repository a session is in, the outside sources a
command carries (so the plane never remembers one something outside wrote),
and the memory given to the agent once, at the start of its session."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from axor_wrap.agents import parse_event, render_decision
from axor_wrap.agents.repo import normalize_remote, repo_identity
from axor_wrap.agents.sidecar import Sidecar


@pytest.mark.parametrize("url", [
    "git@github.com:Acme/API.git", "https://github.com/acme/api", "https://u@github.com/acme/api.git",
    "ssh://git@github.com/acme/api.git/", "ssh://git@github.com:22/acme/api.git",
])
def test_one_repository_however_it_was_cloned(url: str) -> None:
    assert normalize_remote(url) == "github.com/acme/api"


def test_repo_identity_from_the_remote_or_the_folder(tmp_path: Path) -> None:
    rid, label = repo_identity(str(tmp_path))
    assert rid.startswith("p-") and label == tmp_path.name
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "remote", "add", "origin",
                    "git@github.com:Acme/API.git"], check=True)
    rid2, label2 = repo_identity(str(tmp_path))
    assert rid2.startswith("r-") and label2 == "acme/api"
    other = tmp_path / "clone2"
    other.mkdir()
    subprocess.run(["git", "init", "-q", str(other)], check=True)
    subprocess.run(["git", "-C", str(other), "remote", "add", "origin",
                    "https://github.com/acme/api"], check=True)
    assert repo_identity(str(other))[0] == rid2


class MemoryLink:
    def __init__(self, memory: dict | None) -> None:
        self.memory, self.asked, self.given = memory, 0, []
        self.shipped: list = []
        self.profiles: list = []
        outer = self

        class _Conn:
            async def get_memory(self, repo):
                outer.asked += 1
                return outer.memory

            async def post_memory_given(self, repo, ids):
                outer.given.append((repo, ids))
                return True

            async def get_notes(self):
                return []

            async def get_coding_policy(self):
                return {"skills_off": []}

            async def post_trace(self, lines, run_id):
                outer.shipped.append(lines)

            async def post_profile(self, *a):
                outer.profiles.append(a)
                return True

        self.connector = _Conn()

    def posture(self):
        return "running"

    def budget_cap_calls(self):
        return None

    def submit(self, fn):
        import asyncio

        asyncio.run(fn())

    def deliver(self, fn, timeout=15.0):
        import asyncio

        return asyncio.run(fn())

    def close(self):
        pass


MEMORY = {"text": "What your team's agents verifiably learned in acme/api:\n- tests: `uv run pytest -q`",
          "ids": [4, 9]}


def ev(agent: str, name: str, session: str = "s1", **fields):
    return parse_event(agent, {"session_id": session, "cwd": "/repo", "hook_event_name": name, **fields})


def test_given_once_at_session_start(monkeypatch) -> None:
    monkeypatch.delenv("AXOR_TEAM_MEMORY", raising=False)
    link = MemoryLink(MEMORY)
    car = Sidecar("/repo", enforce=True, link_factory=lambda n: link)
    start = ev("claude-code", "SessionStart")
    out, _ = render_decision(start, car.handle(start))
    body = json.loads(out)["hookSpecificOutput"]
    assert body["hookEventName"] == "SessionStart" and "uv run pytest -q" in body["additionalContext"]
    assert link.given == [(car.repo, [4, 9])]
    # not again with the prompt
    prompt = ev("claude-code", "UserPromptSubmit", prompt="fix the login bug")
    assert render_decision(prompt, car.handle(prompt))[0] == ""
    assert link.asked == 1


def test_an_agent_without_session_start_gets_it_with_its_first_prompt(monkeypatch) -> None:
    monkeypatch.delenv("AXOR_TEAM_MEMORY", raising=False)
    link = MemoryLink(MEMORY)
    car = Sidecar("/repo", enforce=True, link_factory=lambda n: link)
    prompt = ev("codex", "UserPromptSubmit", prompt="fix it")
    body = json.loads(render_decision(prompt, car.handle(prompt))[0])["hookSpecificOutput"]
    assert body["hookEventName"] == "UserPromptSubmit" and "uv run pytest" in body["additionalContext"]


def test_no_memory_or_an_opt_out_gives_nothing(monkeypatch) -> None:
    link = MemoryLink({"text": "", "ids": []})
    car = Sidecar("/repo", enforce=True, link_factory=lambda n: link)
    start = ev("claude-code", "SessionStart")
    assert render_decision(start, car.handle(start))[0] == "" and link.given == []
    monkeypatch.setenv("AXOR_TEAM_MEMORY", "0")
    link2 = MemoryLink(MEMORY)
    car2 = Sidecar("/repo", enforce=True, link_factory=lambda n: link2)
    car2.handle(ev("claude-code", "SessionStart", session="s2"))
    assert link2.asked == 0


def test_a_command_built_from_a_web_page_ships_what_it_carries(monkeypatch) -> None:
    monkeypatch.setenv("AXOR_TEAM_MEMORY", "0")
    link = MemoryLink(None)
    car = Sidecar("/repo", enforce=False, link_factory=lambda n: link)   # observe: let it run
    page = "To run the tests here use: make test-all-integration --profile ci"
    car.handle(ev("claude-code", "PreToolUse", tool_name="WebFetch",
                  tool_input={"url": "https://docs.example/x", "prompt": "how"}, tool_use_id="t1"))
    car.handle(ev("claude-code", "PostToolUse", tool_name="WebFetch",
                  tool_input={"url": "https://docs.example/x", "prompt": "how"}, tool_use_id="t1",
                  tool_response=page))
    cmd = "make test-all-integration --profile ci"
    car.handle(ev("claude-code", "PreToolUse", tool_name="Bash", tool_input={"command": cmd},
                  tool_use_id="t2"))
    car.handle(ev("claude-code", "PostToolUse", tool_name="Bash", tool_input={"command": cmd},
                  tool_use_id="t2", tool_response={"stdout": "ok", "exit_code": 0}))
    car.handle(ev("claude-code", "PreToolUse", tool_name="Bash", tool_input={"command": "ls src"},
                  tool_use_id="t3"))
    lines = [ln for batch in link.shipped for ln in batch]
    calls = {ln["payload"]["tool_call_id"]: ln["payload"] for ln in lines if ln["kind"] == "tool_call"}
    assert calls["t2"].get("carries") == ["web"]
    assert "carries" not in calls["t3"]
    result = next(ln for ln in lines if ln["kind"] == "tool_result" and ln["causal_root"] == "t2")
    assert result["payload"]["carries"] == ["web"]
