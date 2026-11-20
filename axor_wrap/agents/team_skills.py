"""Skills turned ON for the team from the Control Plane.

The plane keeps a skill's files (uploaded with ``axor-wrap skill share``) and,
once someone turns it on for the team, names it with its version in the coding
policy every sidecar fetches. Each sidecar then installs it into the agent's
personal skills folder — ``~/.claude/skills/<name>``, ``~/.codex/skills/<name>``
— and keeps it at that version; turned back off, the folder goes.

Only folders this module wrote are ever touched: each carries a marker file
(``.axor-team.json``). A developer's own skill with the same name is left
alone and reported, never overwritten. ``AXOR_TEAM_SKILLS=0`` opts a machine
out. A team skill is still governed like any other: turned off for the team,
the sidecar refuses it, and its commands meet the same rules.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath

_log = logging.getLogger("axor_wrap.agents.team_skills")

MARKER = ".axor-team.json"
ENV_OPT_OUT = "AXOR_TEAM_SKILLS"
_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
_MAX_FILES = 64
_MAX_BYTES = 512_000


def enabled() -> bool:
    return os.environ.get(ENV_OPT_OUT, "1").lower() not in ("0", "off", "false", "no")


def skills_dir(agent: str) -> Path:
    """The agent's personal skills folder."""
    home = Path(os.environ.get("HOME") or Path.home())
    return home / (".codex" if agent == "codex" else ".claude") / "skills"


def wanted_from(policy: dict | None) -> dict[str, str] | None:
    """``{name: version}`` from the policy's ``skills_team``; None when the
    plane said nothing about it (an older plane), so nothing is removed."""
    if not isinstance(policy, dict) or not isinstance(policy.get("skills_team"), list):
        return None
    out: dict[str, str] = {}
    for item in policy["skills_team"]:
        if isinstance(item, dict) and _NAME.match(str(item.get("name", ""))):
            out[str(item["name"])] = str(item.get("version", ""))
    return out


def installed(agent: str) -> dict[str, str]:
    """The team skills this machine has: ``{name: version}``."""
    root = skills_dir(agent)
    out: dict[str, str] = {}
    if not root.is_dir():
        return out
    for d in root.iterdir():
        marker = d / MARKER
        if d.is_dir() and marker.is_file():
            try:
                out[d.name] = str(json.loads(marker.read_text(encoding="utf-8")).get("version", ""))
            except (OSError, ValueError, AttributeError):
                out[d.name] = ""
    return out


def plan(agent: str, wanted: dict[str, str]) -> tuple[list[str], list[str], list[str]]:
    """What to install (missing or another version), what to remove (ours, no
    longer on), and what is the developer's own folder of the same name."""
    have = installed(agent)
    root = skills_dir(agent)
    own = sorted(n for n in wanted if n not in have and (root / n).exists())
    install = sorted(n for n, v in wanted.items() if n not in own and have.get(n) != v)
    remove = sorted(n for n in have if n not in wanted)
    return install, remove, own


def _safe(path: str) -> PurePosixPath | None:
    p = PurePosixPath(path.replace("\\", "/"))
    if p.is_absolute() or not p.parts or any(part in ("", ".", "..") or part.startswith(".")
                                             for part in p.parts):
        return None
    return p


def install(agent: str, bundle: dict) -> bool:
    """Write one team skill (``{name, version, files: [{path, content}]}``)
    into the agent's skills folder, replacing only an earlier team copy."""
    name = str(bundle.get("name", ""))
    files = bundle.get("files")
    if not _NAME.match(name) or not isinstance(files, list) or not files or len(files) > _MAX_FILES:
        return False
    entries: list[tuple[PurePosixPath, str]] = []
    total = 0
    for f in files:
        rel = _safe(str(f.get("path", ""))) if isinstance(f, dict) else None
        content = f.get("content") if isinstance(f, dict) else None
        if rel is None or not isinstance(content, str):
            return False
        total += len(content)
        entries.append((rel, content))
    if total > _MAX_BYTES or not any(str(r).lower() == "skill.md" for r, _ in entries):
        return False
    root = skills_dir(agent)
    target = root / name
    if target.exists() and not (target / MARKER).is_file():
        _log.warning("axor: team skill %s not installed — %s is your own", name, target)
        return False
    root.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=f".{name}.", dir=root))
    try:
        for rel, content in entries:
            out = tmp.joinpath(*rel.parts)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(content, encoding="utf-8")
        (tmp / MARKER).write_text(json.dumps({"name": name, "version": bundle.get("version", ""),
                                              "from": "axor control plane"}), encoding="utf-8")
        if target.exists():
            shutil.rmtree(target)
        tmp.rename(target)
    except OSError as exc:
        _log.warning("axor: team skill %s not installed: %s", name, exc)
        shutil.rmtree(tmp, ignore_errors=True)
        return False
    return True


def remove(agent: str, name: str) -> bool:
    """Remove a team skill this module installed; never anything else."""
    if not _NAME.match(name):
        return False
    target = skills_dir(agent) / name
    if not (target / MARKER).is_file():
        return False
    shutil.rmtree(target, ignore_errors=True)
    return not target.exists()
