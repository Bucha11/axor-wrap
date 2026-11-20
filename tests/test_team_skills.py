"""Skills turned on for the team: each sidecar installs them into the agent's
skills folder at the version the plane names, and removes them when turned
back off — never touching a developer's own folder."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from axor_wrap.agents import parse_event, team_skills
from axor_wrap.agents.sidecar import Sidecar

SKILL = "---\nname: changelog-entries\ndescription: write the changelog entry\n---\nAdd one line.\n"


def bundle(version: str = "v1", name: str = "changelog-entries", **over) -> dict:
    return {"name": name, "version": version,
            "files": [{"path": "SKILL.md", "content": SKILL},
                      {"path": "templates/entry.md", "content": "- {change}\n"}], **over}


@pytest.fixture(autouse=True)
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv(team_skills.ENV_OPT_OUT, raising=False)
    return tmp_path


def test_install_writes_the_files_and_a_marker(home: Path) -> None:
    assert team_skills.install("claude-code", bundle())
    d = home / ".claude" / "skills" / "changelog-entries"
    assert (d / "SKILL.md").read_text() == SKILL
    assert (d / "templates" / "entry.md").is_file()
    assert team_skills.installed("claude-code") == {"changelog-entries": "v1"}
    assert team_skills.install("codex", bundle())
    assert (home / ".codex" / "skills" / "changelog-entries" / "SKILL.md").is_file()


def test_a_developers_own_skill_is_never_overwritten_or_removed(home: Path) -> None:
    own = home / ".claude" / "skills" / "changelog-entries"
    own.mkdir(parents=True)
    (own / "SKILL.md").write_text("mine")
    assert not team_skills.install("claude-code", bundle())
    assert (own / "SKILL.md").read_text() == "mine"
    assert team_skills.plan("claude-code", {"changelog-entries": "v1"}) == ([], [], ["changelog-entries"])
    assert not team_skills.remove("claude-code", "changelog-entries")
    assert own.exists()


@pytest.mark.parametrize("path", ["../escape.md", "/etc/passwd", ".hidden/x", "a/../../b"])
def test_a_bundle_cannot_write_outside_its_folder(home: Path, path: str) -> None:
    bad = bundle()
    bad["files"].append({"path": path, "content": "x"})
    assert not team_skills.install("claude-code", bad)
    assert not (home / ".claude" / "skills" / "changelog-entries").exists()
    assert not team_skills.install("claude-code", bundle(name="../x"))


def test_plan_installs_new_versions_and_removes_what_was_turned_off(home: Path) -> None:
    team_skills.install("claude-code", bundle("v1"))
    team_skills.install("claude-code", bundle("v1", name="old-one"))
    assert team_skills.plan("claude-code", {"changelog-entries": "v2"}) == (
        ["changelog-entries"], ["old-one"], [])


class TeamLink:
    def __init__(self, policy: dict, bundles: dict[str, dict]) -> None:
        self.policy, self.bundles, self.fetched = policy, bundles, []
        self.shipped: list = []
        outer = self

        class _Conn:
            async def get_coding_policy(self):
                return outer.policy

            async def get_skill_bundle(self, name):
                outer.fetched.append(name)
                return outer.bundles.get(name)

            async def post_trace(self, lines, run_id):
                outer.shipped.append(lines)

            async def post_profile(self, *a):
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


def ev(name: str, **fields):
    return parse_event("claude-code", {"session_id": "s1", "cwd": "/repo",
                                       "hook_event_name": name, **fields})


def test_session_start_installs_the_team_skills_and_a_later_policy_removes_them(
        home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    link = TeamLink({"skills_off": [], "skills_team": [{"name": "changelog-entries", "version": "v1"}]},
                    {"changelog-entries": bundle("v1")})
    car = Sidecar("/repo", enforce=True, link_factory=lambda n: link)
    assert car.handle(ev("SessionStart"))["allow"]
    d = home / ".claude" / "skills" / "changelog-entries"
    assert json.loads((d / ".axor-team.json").read_text())["version"] == "v1"
    # nothing to do the next time: not fetched again
    monkeypatch.setattr("axor_wrap.agents.sidecar.POLICY_TTL", 0.0)
    car.handle(ev("PreToolUse", tool_name="Read", tool_input={"file_path": "a.py"}, tool_use_id="t1"))
    assert link.fetched == ["changelog-entries"]
    # a new version is fetched; a stale answer (another version) is not installed
    link.policy = {"skills_team": [{"name": "changelog-entries", "version": "v2"}]}
    link.bundles["changelog-entries"] = bundle("v2")
    car.handle(ev("PreToolUse", tool_name="Read", tool_input={"file_path": "a.py"}, tool_use_id="t2"))
    assert team_skills.installed("claude-code") == {"changelog-entries": "v2"}
    # turned back off for the team: the folder goes
    link.policy = {"skills_team": []}
    car.handle(ev("PreToolUse", tool_name="Read", tool_input={"file_path": "a.py"}, tool_use_id="t3"))
    assert not d.exists()


def test_an_older_plane_or_an_opt_out_changes_nothing(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    team_skills.install("claude-code", bundle("v1"))
    link = TeamLink({"skills_off": []}, {})            # no skills_team: an older plane
    car = Sidecar("/repo", enforce=True, link_factory=lambda n: link)
    car.handle(ev("SessionStart"))
    assert team_skills.installed("claude-code") == {"changelog-entries": "v1"}
    monkeypatch.setenv(team_skills.ENV_OPT_OUT, "0")
    link.policy = {"skills_team": [{"name": "other", "version": "v1"}]}
    car.handle(ev("SessionStart"))
    assert link.fetched == [] and team_skills.installed("claude-code") == {"changelog-entries": "v1"}


def test_the_connector_a_real_sidecar_holds_can_fetch_a_bundle() -> None:
    # the sidecar's link carries a PlaneConnector, not a PlaneClient: a method
    # only on the client failed live while every fake passed
    from axor_wrap.connect import PlaneConnector
    from axor_wrap.plane.client import PlaneClient

    for name in ("get_coding_policy", "get_skill_bundle"):
        assert callable(getattr(PlaneConnector, name)) and callable(getattr(PlaneClient, name))
