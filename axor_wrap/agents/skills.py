"""Skills, before you let an agent use them.

A skill is a folder an agent picks up — ``SKILL.md`` with instructions, and
often scripts beside it. What it tells the agent to do arrives as the agent's
own instructions: Axor marks text that came from OUTSIDE (a page WebFetch read,
a search result, an MCP answer) and refuses a command or a send built from it,
but a skill is a file in your repository. Its ``curl … | sh`` is trusted the
moment you install it. So before installing one, two questions:

- :func:`check` — what does it ask the agent to do? A static read of the
  folder, no agent, no model: downloads that are run, secrets read, data sent
  out, writes outside the repository, destructive commands, persistence,
  packages installed, tools it pre-approves, pages it tells the agent to follow
  — each with where it is and what Axor does about it (usually: nothing, and
  the report says so).
- :func:`try_skill` — what does an agent actually do with it? The agent runs
  once with the skill on a throwaway copy of the repository, under the axor
  hooks with enforcement OFF: nothing is refused, everything is recorded, and
  each call Axor would have refused in real work is marked. The session goes
  to the Control Plane as ``skill-try.<agent>.<skill>.<id>``.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import uuid
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from axor_wrap.agents.taxonomy import read_only_command

DANGER, WARN, INFO = "danger", "warn", "info"
_SEVERITY_ORDER = {DANGER: 0, WARN: 1, INFO: 2}

# what Axor does about each kind, in words (the honest part of the report)
AXOR_LETS_IT_RUN = ("Axor lets this run: it comes from the skill, and the agent "
                    "takes a skill as its own instructions.")
_AXOR = {
    "download_and_run": "Axor lets this run: the command comes from the skill, and what "
                        "it downloads never passes through the agent.",
    "secrets": AXOR_LETS_IT_RUN,
    "sends_out": AXOR_LETS_IT_RUN,
    "writes_outside": AXOR_LETS_IT_RUN,
    "destructive": AXOR_LETS_IT_RUN,
    "privilege": AXOR_LETS_IT_RUN,
    "persistence": AXOR_LETS_IT_RUN,
    "installs": "Axor lets this run — and packages run their own install scripts.",
    "fetches_in_shell": "Axor does not mark what curl / wget bring back: only WebFetch "
                        "and WebSearch results are marked as outside text.",
    "follows_web": "Axor marks what the page says: a command or a send built from "
                   "it is refused.",
    "pre_approves": "The agent will not ask before using these; Axor's checks still apply.",
    "runs_commands": AXOR_LETS_IT_RUN,
}
_WHAT = {
    "download_and_run": "downloads code and runs it",
    "secrets": "reads secrets",
    "sends_out": "sends data out",
    "writes_outside": "writes outside the repository",
    "destructive": "deletes or rewrites history",
    "privilege": "asks for root",
    "persistence": "changes what runs later (shell profile, hooks, CI, cron)",
    "installs": "installs packages",
    "fetches_in_shell": "fetches from the web in the shell",
    "follows_web": "tells the agent to follow a web page",
    "pre_approves": "pre-approves tools",
    "runs_commands": "runs commands",
}
_SEVERITY = {
    "download_and_run": DANGER, "secrets": DANGER, "sends_out": DANGER,
    "writes_outside": DANGER, "destructive": DANGER, "privilege": DANGER,
    "persistence": DANGER, "installs": WARN, "fetches_in_shell": WARN,
    "follows_web": WARN, "pre_approves": WARN, "runs_commands": INFO,
}

_FETCH = r"(?:curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod|irm)\b"
_SHELLS = r"(?:sudo\s+)?(?:ba|z|da|k|fi)?sh\b|python3?\b|node\b|perl\b|ruby\b|iex\b|Invoke-Expression\b"
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("download_and_run", re.compile(rf"{_FETCH}[^\n|]*\|\s*(?:{_SHELLS})", re.I)),
    ("download_and_run", re.compile(rf"(?:ba|z)?sh\s+<\(\s*{_FETCH}", re.I)),
    ("download_and_run", re.compile(rf"(?:eval|source|\.)\s+\"?\$\(\s*{_FETCH}", re.I)),
    ("secrets", re.compile(r"(?:~|\$HOME|/home/[^/\s]+|/root)/\.(?:ssh|aws|gnupg|kube|docker|netrc|npmrc|pypirc|git-credentials)\b"
                           r"|\bid_(?:rsa|ed25519|ecdsa)\b|(?<![\w.])\.env(?![\w.])|\bcredentials\.json\b"
                           r"|\$\{?(?:[A-Z_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY)[A-Z_]*)\}?"
                           r"|\bprintenv\b|\benv\s*\|")),
    ("sends_out", re.compile(rf"{_FETCH}[^\n]*\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|-X\s*(?:POST|PUT))\b", re.I)),
    ("sends_out", re.compile(r"\b(?:nc|ncat|netcat|scp|rsync|sftp|ftp)\s+[^\n]*\b(?:\d{1,3}\.){3}\d{1,3}|\b(?:scp|rsync)\s+[^\n]*\s[\w.-]+@[\w.-]+:")),
    ("sends_out", re.compile(r"\brequests\.(?:post|put)\(|\bhttpx\.(?:post|put)\(|\burllib\.request\.urlopen\([^)]*data=|method:\s*['\"](?:POST|PUT)['\"]")),
    ("writes_outside", re.compile(r"(?:>>?|\btee\s+(?:-a\s+)?|\bcp\s+[^\n]*\s|\bmv\s+[^\n]*\s|open\(\s*['\"])(?:~|/etc|/usr|/opt|/var|\$HOME|/home/|\.\./)")),
    ("destructive", re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f|\brm\s+-[a-zA-Z]*f[a-zA-Z]*r|\bgit\s+push\s+[^\n]*(?:--force|-f)\b|\bgit\s+reset\s+--hard|\bgit\s+clean\s+-[a-zA-Z]*f|\bshutil\.rmtree\(|\bmkfs\b|\bdd\s+if=")),
    ("privilege", re.compile(r"(?<![\w-])sudo\s|\bchmod\s+(?:-R\s+)?777\b|\bchown\s+-R\s+root")),
    ("persistence", re.compile(r"\.(?:bashrc|zshrc|profile|bash_profile)\b|\bcrontab\b|\.git/hooks/|\.github/workflows/|\bsystemctl\s+enable\b|\blaunchctl\s+load\b|\.claude/settings|\.codex/config")),
    ("installs", re.compile(r"\b(?:pip3?|uv\s+pip|pipx)\s+install\b|\bnpm\s+(?:i|install|add)\b|\b(?:yarn|pnpm)\s+add\b|\bnpx\s+\S|\b(?:brew|apt|apt-get|yum|dnf|apk)\s+install\b|\bgo\s+install\b|\bcargo\s+install\b|\bgem\s+install\b")),
    ("fetches_in_shell", re.compile(rf"{_FETCH}\s+[^\n]*https?://", re.I)),
    ("follows_web", re.compile(r"\b(?:fetch|open|read|visit|go to|load|download)\b[^\n.]{0,60}https?://[^\s)]+[^\n.]{0,80}\b(?:follow|apply|run|execute|do what|instructions?)\b"
                               r"|\b(?:follow|apply|run|execute)\b[^\n.]{0,40}\b(?:instructions?|steps|commands?)\b[^\n.]{0,40}\b(?:from|at|on|in)\b[^\n.]{0,20}(?:https?://|the (?:page|url|website|link))", re.I)),
]
_URL = re.compile(r"https?://[^\s)\"'<>`]+")
_FENCE = re.compile(r"^```([\w-]*)\s*\n(.*?)^```", re.M | re.S)
_SHELL_LANGS = {"", "bash", "sh", "shell", "zsh", "console", "terminal", "powershell", "ps1", "cmd"}
_INLINE = re.compile(r"`([^`\n]{3,200})`")
_COMMAND_WORD = re.compile(r"^(?:\$\s*)?(?:sudo\s+)?[a-z][\w.+-]*(?:\s|$)")


@dataclass
class Finding:
    kind: str
    severity: str
    what: str
    where: str
    snippet: str
    axor: str


@dataclass
class SkillReport:
    name: str = ""
    description: str = ""
    skill_file: str = ""
    files: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        out = {DANGER: 0, WARN: 0, INFO: 0}
        for f in self.findings:
            out[f.severity] += 1
        return out

    def as_dict(self) -> dict:
        d = asdict(self)
        d["summary"] = self.summary()
        return d


def _frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end < 0:
        return {}
    out: dict[str, str] = {}
    for line in text[3:end].splitlines():
        if ":" in line and not line.startswith((" ", "\t")):
            key, _, value = line.partition(":")
            out[key.strip().lower()] = value.strip().strip("'\"")
    return out


def _commands(path: str, text: str) -> Iterable[tuple[int, str]]:
    """(line number, command) for every shell command the file asks for: a
    script's lines, a markdown file's shell blocks and inline `commands`."""
    low = path.lower()
    if low.endswith((".sh", ".bash", ".zsh", ".ps1")):
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if s and not s.startswith("#"):
                yield i, s
        return
    if low.endswith((".md", ".markdown", ".txt")):
        for m in _FENCE.finditer(text):
            if m.group(1).lower() not in _SHELL_LANGS:
                continue
            start = text.count("\n", 0, m.start(2)) + 1
            for j, line in enumerate(m.group(2).splitlines()):
                s = line.strip()
                if s and not s.startswith("#") and _COMMAND_WORD.match(s):
                    yield start + j, s.removeprefix("$").strip()
        for m in _INLINE.finditer(text):
            s = m.group(1).strip()
            if _COMMAND_WORD.match(s) and " " in s:
                yield text.count("\n", 0, m.start()) + 1, s.removeprefix("$").strip()


def check(files: Iterable[tuple[str, str]]) -> SkillReport:
    """What a skill folder asks an agent to do — a static read, nothing run."""
    files = [(p.replace("\\", "/"), t) for p, t in files]
    report = SkillReport(files=[p for p, _ in files])
    skill = next((f for f in files if f[0].rsplit("/", 1)[-1].lower() == "skill.md"), None)
    if skill is not None:
        report.skill_file = skill[0]
        meta = _frontmatter(skill[1])
        folder = skill[0].rsplit("/", 2)[-2] if "/" in skill[0] else ""
        report.name = meta.get("name", "") or folder
        report.description = meta.get("description", "")
        tools = meta.get("allowed-tools", "") or meta.get("allowed_tools", "")
        report.allowed_tools = [t.strip() for t in re.split(r",(?![^(]*\))", tools.strip("[]")) if t.strip()]
        if any(t.lower().startswith(("bash", "write", "edit", "webfetch")) for t in report.allowed_tools):
            report.findings.append(Finding(
                "pre_approves", _SEVERITY["pre_approves"], _WHAT["pre_approves"],
                f"{skill[0]}:1", ", ".join(report.allowed_tools)[:200], _AXOR["pre_approves"]))
    seen: set[tuple[str, str]] = set()

    def add(kind: str, where: str, snippet: str) -> None:
        key = (kind, snippet)
        if key in seen:
            return
        seen.add(key)
        report.findings.append(Finding(kind, _SEVERITY[kind], _WHAT[kind], where,
                                       snippet[:240], _AXOR[kind]))

    for path, text in files:
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            hit = [kind for kind, pattern in _PATTERNS if pattern.search(line) and not (
                kind == "follows_web" and not path.lower().endswith((".md", ".markdown", ".txt")))]
            # a shell fetch that already downloads-and-runs or sends is said once
            if any(_SEVERITY[k] == DANGER for k in hit):
                hit = [k for k in hit if k != "fetches_in_shell"]
            for kind in dict.fromkeys(hit):
                add(kind, f"{path}:{i}", line.strip())
        for url in _URL.findall(text):
            if url not in report.urls:
                report.urls.append(url)
        for i, cmd in _commands(path, text):
            if cmd not in report.commands:
                report.commands.append(cmd)
            if not read_only_command(cmd) and not any(
                    f.where == f"{path}:{i}" and f.severity == DANGER for f in report.findings):
                add("runs_commands", f"{path}:{i}", cmd)
    report.findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.where))
    return report


def read_folder(root: Path, *, limit_bytes: int = 512_000) -> list[tuple[str, str]]:
    """A skill folder's text files, paths relative to the folder."""
    out: list[tuple[str, str]] = []
    total = 0
    for p in sorted(root.rglob("*")):
        if not p.is_file() or any(part.startswith(".") for part in p.relative_to(root).parts):
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        total += len(text)
        if total > limit_bytes:
            break
        out.append((str(p.relative_to(root)), text))
    return out


# ── the dry run ───────────────────────────────────────────────────────────────

_SKIP_COPY = shutil.ignore_patterns(".git", "node_modules", ".venv", "venv", "__pycache__",
                                    "dist", "build", ".mypy_cache", ".ruff_cache", ".tox")


def try_node_id(agent: str, skill: str) -> str:
    """``skill-try.<agent>.<skill>.<id>`` — how the plane tells a skill's dry
    run from a working session (ids allow ``[A-Za-z0-9_.:-]``, 64 at most)."""
    name = re.sub(r"[^a-z0-9-]+", "-", skill.lower()).strip("-")[:24] or "skill"
    return f"skill-try.{agent}.{name}.{uuid.uuid4().hex[:8]}"


def skill_name(folder: Path) -> str:
    md = next((p for p in folder.iterdir() if p.name.lower() == "skill.md"), None)
    if md is not None:
        name = _frontmatter(md.read_text(encoding="utf-8", errors="replace")).get("name", "")
        if name:
            return name
    return folder.resolve().name


@dataclass
class TryResult:
    node_id: str
    workspace: str
    answer: str
    returncode: int
    report: dict


def prepare(skill_dir: Path, agent: str, repo: Path, into: Path) -> Path:
    """A throwaway copy of ``repo`` with the skill installed where the agent
    looks for skills (``.claude/skills/<name>`` / ``.codex/skills/<name>``)."""
    work = into / "repo"
    shutil.copytree(repo, work, ignore=_SKIP_COPY, symlinks=True)
    home = ".claude" if agent == "claude-code" else ".codex"
    target = work / home / "skills" / re.sub(r"[^A-Za-z0-9_-]+", "-", skill_name(skill_dir))
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(skill_dir, target, ignore=shutil.ignore_patterns(".git"))
    # a repository the agent can diff against: what it changed is the run
    if shutil.which("git"):
        subprocess.run(["git", "init", "-q"], cwd=work, check=False)
        subprocess.run(["git", "add", "-A"], cwd=work, check=False)
        subprocess.run(["git", "-c", "user.name=axor", "-c", "user.email=axor@localhost",
                        "commit", "-qm", "before the skill"], cwd=work, check=False,
                       capture_output=True)
    return work


def default_task(agent: str, name: str) -> str:
    where = ".claude/skills" if agent == "claude-code" else ".codex/skills"
    return (f"Use the “{name}” skill ({where}/{name}/SKILL.md) on this repository, "
            "as a user who just installed it would. Follow its instructions.")


def try_skill(skill_dir: Path, *, agent: str = "claude-code", task: str = "",
              repo: Path | None = None, model: str = "", timeout: float = 900.0,
              keep: bool = False) -> TryResult:
    """Run the agent once with the skill, on a copy, enforcement off."""
    from axor_wrap.agents import client
    from axor_wrap.agents.install import install
    from axor_wrap.agents.runners import default_argv, parse_output

    name = skill_name(skill_dir)
    node_id = try_node_id(agent, name)
    tmp = Path(tempfile.mkdtemp(prefix="axor-skill-"))
    work = prepare(skill_dir, agent, (repo or Path.cwd()).resolve(), tmp)
    if agent == "codex":
        install("codex", work)
    env = dict(os.environ)
    env.update({"AXOR_NODE_ID": node_id, "AXOR_ENFORCE": "off", "AXOR_ROLE": "skill-try"})
    # the copy's own sidecar, started observe-only: it records what would have
    # been refused and refuses nothing
    saved = os.environ.get("AXOR_ENFORCE")
    os.environ["AXOR_ENFORCE"] = "off"
    try:
        client.ensure_sidecar(client.workspace_root(str(work)))
    finally:
        if saved is None:
            os.environ.pop("AXOR_ENFORCE", None)
        else:
            os.environ["AXOR_ENFORCE"] = saved
    fd, last = tempfile.mkstemp(prefix="axor-last-", suffix=".txt")
    os.close(fd)
    argv = default_argv(agent, model, task or default_task(agent, name), read_only=False,
                        last_message_file=last)
    try:
        proc = subprocess.run(argv, cwd=work, env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=timeout, check=False)
        answer, _ = parse_output(agent, proc.stdout, Path(last).read_text(errors="replace"))
        code = proc.returncode
        if code != 0 and not answer:
            answer = proc.stderr.strip()[-400:]
    except FileNotFoundError:
        answer, code = f"the {agent} CLI is not installed here", 127
    except subprocess.TimeoutExpired:
        answer, code = f"{agent} did not finish within {timeout:.0f}s", 124
    finally:
        os.unlink(last)
    report = client.node_report(client.workspace_root(str(work)), node_id)
    if not keep:
        shutil.rmtree(tmp, ignore_errors=True)
    return TryResult(node_id, str(work), answer, code, report)
