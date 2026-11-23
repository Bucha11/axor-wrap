"""Controls on a running session: a pause holds the agent's call until it is
resumed (no lost turn), a stop ends Claude Code's turn, a tree's orchestrator
passes its root's pause / stop to the nodes it runs, the team's brake holds
every agent, and a call held by a control is marked as one — not a refusal."""
from __future__ import annotations

import json
import threading
import time

import pytest

from axor_wrap.agents import parse_event, render_decision
from axor_wrap.agents.sidecar import Sidecar


class _Link:
    def __init__(self) -> None:
        self.state = "running"
        self.policy: dict = {}
        self.shipped: list = []
        outer = self

        class _Conn:
            async def get_coding_policy(self):
                return outer.policy

            async def post_trace(self, lines, run_id):
                outer.shipped.extend(lines)

            def __getattr__(self, name):
                async def nothing(*a, **k):
                    return None
                return nothing

        self.connector = _Conn()

    def posture(self):
        return self.state

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


def _pre(car: Sidecar, n: int = 0, agent: str = "claude-code") -> dict:
    ev = parse_event(agent, {"session_id": "s1", "cwd": "/repo", "hook_event_name": "PreToolUse",
                             "tool_name": "Read", "tool_input": {"file_path": "a.py"},
                             "tool_use_id": f"t{n}"})
    return car.handle(ev)


@pytest.fixture
def car_link():
    link = _Link()
    return Sidecar("/repo", enforce=True, link_factory=lambda n: link), link


def test_a_pause_holds_the_call_until_resumed(car_link, monkeypatch) -> None:
    monkeypatch.setattr("axor_wrap.agents.sidecar.HOLD_SECONDS", 5.0)
    car, link = car_link
    _pre(car, 0)                       # the session exists
    link.state = "paused"
    threading.Timer(0.8, lambda: setattr(link, "state", "running")).start()
    t = time.time()
    out = _pre(car, 1)
    assert out["allow"] is True and 0.5 < time.time() - t < 4


def test_a_pause_that_lasts_is_refused_as_a_control(car_link) -> None:
    car, link = car_link
    _pre(car, 0)
    link.state = "paused"
    out = _pre(car, 1)
    assert out["allow"] is False and "paused" in out["reason"]
    calls = [x["payload"] for x in link.shipped if x.get("kind") == "tool_call"]
    assert calls[-1].get("control") == "paused"


def test_a_stop_ends_claude_codes_turn(car_link) -> None:
    car, link = car_link
    link.state = "stopped"
    ev = parse_event("claude-code", {"session_id": "s1", "cwd": "/repo", "hook_event_name": "PreToolUse",
                                     "tool_name": "Read", "tool_input": {"file_path": "a.py"},
                                     "tool_use_id": "t1"})
    out, _ = render_decision(ev, car.handle(ev))
    body = json.loads(out)
    assert body["continue"] is False and "stopped" in body["stopReason"]
    assert body["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_a_tree_passes_its_stop_to_the_nodes_it_runs(car_link) -> None:
    car, link = car_link
    _pre(car, 0)
    node = next(iter(car.by_node))
    car.hold([node], "paused")
    assert "its tree is paused" in _pre(car, 1)["reason"]
    car.hold([node], "running")
    assert _pre(car, 2)["allow"] is True
    car.hold([node], "stopped")
    car.hold([node], "running")      # a stop stands
    assert "its tree was stopped" in _pre(car, 3)["reason"]


def test_the_teams_brake_holds_every_agent(car_link) -> None:
    car, link = car_link
    link.policy = {"brake": {"on": True, "by": "lee@acme.io"}}
    out = _pre(car, 0)
    assert out["allow"] is False and "your team's admin paused every agent" in out["reason"]
    link.policy = {}
    car._coding_policy = (0.0, None)     # the next fetch sees it lifted
    assert _pre(car, 1)["allow"] is True


# ── a subagent (Claude Code's Agent tool) is a branch of its session ──────────

class _Recording(_Link):
    def __init__(self, node: str) -> None:
        super().__init__()
        self.node = node
        self.said: list = []
        outer = self

        class _Conn:
            async def get_coding_policy(self):
                return outer.policy

            async def post_trace(self, lines, run_id):
                outer.shipped.extend(lines)

            def __getattr__(self, name):
                if name not in ("post_profile", "post_title"):
                    raise AttributeError(name)

                async def record(*a, **k):
                    outer.said.append((name, a, k))
                return record

        self.connector = _Conn()


def _ev(kind: str, n: int = 0, sub: str = "", **extra) -> dict:
    data = {"session_id": "s1", "cwd": "/repo", "hook_event_name": kind,
            "tool_name": "Read", "tool_input": {"file_path": f"f{n}.py"}, "tool_use_id": f"t{n}"}
    if sub:
        data.update(agent_id=sub, agent_type="Explore")
    data.update(extra)
    return parse_event("claude-code", data)


@pytest.fixture
def car_links():
    links: dict[str, _Recording] = {}

    def factory(node: str) -> _Recording:
        links[node] = _Recording(node)
        return links[node]

    return Sidecar("/repo", enforce=True, link_factory=factory), links


def test_a_subagent_is_a_node_of_its_own_under_its_session(car_links) -> None:
    car, links = car_links
    car.handle(_ev("PreToolUse", 0, tool_name="Agent", tool_input={
        "subagent_type": "Explore", "description": "find the auth module",
        "prompt": "Find where login is handled"}))
    assert car.handle(_ev("PreToolUse", 1, sub="agent-abc12345"))["allow"] is True
    car.handle(_ev("PostToolUse", 1, sub="agent-abc12345", tool_response={"content": "x"}))
    parent, = [n for n in links if "." not in n]
    sub, = [n for n in links if "." in n]
    assert sub == f"{parent}.Explore-abc12345"
    # its calls are its own, not its session's
    assert any(x.get("kind") == "tool_call" for x in links[sub].shipped)
    assert not any(x.get("kind") == "tool_call" and x["payload"].get("tool") == "Read"
                   for x in links[parent].shipped)
    # the session's trace draws the branch; the subagent names its session
    spawned = [x["payload"] for x in links[parent].shipped if x.get("kind") == "node_spawned"]
    assert spawned and spawned[0]["child_id"] == sub and spawned[0]["role"] == "Explore"
    profile = next(k for name, a, k in links[sub].said if name == "post_profile")
    assert profile == {"parent": parent}
    title = next(a for name, a, k in links[sub].said if name == "post_title")
    assert title == ("Explore: find the auth module",)
    # it ends: its answer closes its run
    car.handle(_ev("SubagentStop", 2, sub="agent-abc12345",
                   last_assistant_message="login is in src/auth.py"))
    assert any(x.get("kind") == "claim" for x in links[sub].shipped)


def test_pausing_a_session_holds_its_subagent_and_a_subagent_stops_alone(car_links) -> None:
    car, links = car_links
    car.handle(_ev("PreToolUse", 0))
    car.handle(_ev("PreToolUse", 1, sub="agent-1"))
    parent, = [n for n in links if "." not in n]
    sub, = [n for n in links if "." in n]
    links[parent].state = "paused"
    held = car.handle(_ev("PreToolUse", 2, sub="agent-1"))
    assert held["allow"] is False and "session that started this subagent is paused" in held["reason"]
    links[parent].state = "running"
    links[sub].state = "stopped"
    out = car.handle(_ev("PreToolUse", 3, sub="agent-1"))
    assert out["allow"] is False and "report what you have" in out["reason"]
    # the subagent ends — not the developer's whole turn
    assert "halt" not in out
    rendered, _ = render_decision(_ev("PreToolUse", 3, sub="agent-1"), out)
    assert '"continue"' not in rendered
    assert car.handle(_ev("PreToolUse", 4))["allow"] is True


def test_a_tree_nodes_report_counts_what_its_subagents_read(car_links) -> None:
    car, links = car_links
    car.handle(_ev("PreToolUse", 0, ))
    car.handle(_ev("PostToolUse", 0, tool_response={"content": "a"}))
    car.handle(_ev("PreToolUse", 1, sub="agent-9"))
    car.handle(_ev("PostToolUse", 1, sub="agent-9", tool_response={"content": "b"}))
    parent, = [n for n in links if "." not in n]
    assert len(car.node_report(parent)["calls"]) == 2
