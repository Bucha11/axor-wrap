"""Calls a coding agent is refused whoever asked for them.

The governor refuses what OUTSIDE text drives — a command built from a page
WebFetch read, a fetch whose URL came from a search result. That leaves what
the agent's own instructions ask for: a skill's ``curl … | sh``, a CLAUDE.md
that says to read ``~/.aws/credentials`` and post it, a task that ends in
``git push --force``. Those are trusted text, and they are the dangerous half.

These rules are checked on every call, before the governor, in every session:
a match is refused (or, with enforcement off, recorded as what would have been
refused). They are deliberately narrow — the things a coding task almost never
needs and an attacker almost always does — so normal work (installs, tests,
``git push``, ``rm -rf node_modules``, ``curl`` an API) passes untouched.

A workspace that needs one turns it off by id, in ``.axor/rules.json``
(``{"allow": ["force_push"]}``) or ``AXOR_ALLOW_RULES=force_push,sudo``.
"""
from __future__ import annotations

import json
import os
import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

_FETCH = r"(?:curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod|irm)\b"
_RUN = r"(?:sudo\s+)?(?:ba|z|da|k|fi)?sh\b|python3?\b|node\b|perl\b|ruby\b|iex\b|Invoke-Expression\b"
DOWNLOAD_AND_RUN = re.compile(
    rf"{_FETCH}[^\n|;]*\|\s*(?:{_RUN})"
    rf"|(?:ba|z)?sh\s+<\(\s*{_FETCH}"
    rf"|(?:eval|source|\.)\s+\"?\$\(\s*{_FETCH}", re.I)

SECRET_PATH = re.compile(
    r"(?:~|\$HOME|\$\{HOME\}|/home/[^/\s]+|/Users/[^/\s]+|/root)/\.(?:ssh|aws|gnupg|kube|docker|azure|"
    r"config/gcloud|netrc|npmrc|pypirc|git-credentials)(?:/|\b)"
    r"|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\bcredentials\.json\b")
# a .env file: reading it puts its keys in the agent's context — copying the
# example into place does not
DOTENV = re.compile(r"(?<![\w.-])\.env(?:\.(?!example\b|sample\b|template\b|dist\b)[\w-]+)?(?![\w.-])")
_READERS = ("cat", "less", "more", "head", "tail", "bat", "grep", "rg", "awk", "sed", "strings",
            "xxd", "base64", "od", "nl", "source", ".", "export", "jq")
# printing the environment, or a secret variable, into the context — using a
# token in a request ($GITHUB_TOKEN in a header) is not reading it
SECRET_ENV = re.compile(
    r"^\s*(?:printenv|env|set|export\s+-p)\s*(?:$|\||>)"
    r"|\b(?:echo|printf)\b[^\n|;]*\$\{?[A-Z_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|PRIVATE_KEY)[A-Z_]*", re.M)

UPLOAD = re.compile(
    rf"{_FETCH}[^\n]*?(?:\s-d\s*@|\s--data(?:-binary|-raw|-urlencode)?[\s=]+@|\s-F\s*['\"]?[\w.-]+=@"
    rf"|\s-T\s|\s--upload-file\b|\s--post-file\b)", re.I)
NET_PIPE = re.compile(r"\|\s*(?:nc|ncat|netcat|socat)\b|\b(?:nc|ncat|netcat)\s+[^\n<]*<")
REMOTE_COPY = re.compile(r"\b(?:scp|rsync|sftp)\b[^\n]*\s(?:[\w.-]+@)?[\w-]+(?:\.[\w-]+)+:")

PROFILES = (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv",
            ".config/fish/config.fish")
AGENT_CONFIG = re.compile(
    r"(?:^|/)\.claude/settings(?:\.local)?\.json$|(?:^|/)\.codex/(?:hooks\.json|config\.toml)$"
    r"|(?:^|/)\.axor/rules\.json$")
PERSIST_CMD = re.compile(
    r"\bcrontab\s+(?!-l\b)|\bsystemctl\s+(?:--user\s+)?enable\b|\blaunchctl\s+(?:load|bootstrap)\b")
SYSTEM_DIRS = ("/etc/", "/usr/", "/bin/", "/sbin/", "/lib/", "/opt/", "/boot/", "/Library/",
               "/System/")
TEMP_DIRS = ("/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/", "/dev/null")


@dataclass(frozen=True)
class Rule:
    id: str
    what: str     # what the call does, in words
    why: str      # why it is refused


def _home() -> str:
    return os.path.expanduser("~")


def _resolve(path: str, root: str) -> str:
    p = path.strip().strip("'\"")
    p = p.replace("${HOME}", "~").replace("$HOME", "~")
    p = os.path.expanduser(p)
    if not os.path.isabs(p):
        p = os.path.join(root, p)
    return os.path.normpath(p)


def _inside(path: str, root: str) -> bool:
    root = os.path.normpath(root)
    return path == root or path.startswith(root.rstrip("/") + "/")


def _temp(path: str) -> bool:
    tmp = os.environ.get("TMPDIR", "")
    return path.startswith(TEMP_DIRS) or bool(tmp and path.startswith(tmp.rstrip("/") + "/"))


def _chunks(command: str) -> list[list[str]]:
    out: list[list[str]] = []
    for chunk in re.split(r"&&|\|\||;|\||\n", command):
        try:
            words = shlex.split(chunk)
        except ValueError:
            words = chunk.split()
        if words:
            out.append(words)
    return out


def _write_targets(command: str) -> list[str]:
    """Where a shell line writes: redirections, tee, cp / mv / ln targets."""
    targets = [m.group(1) for m in re.finditer(r"(?:^|[^<>&0-9])>{1,2}\s*([^\s;&|]+)", command)]
    for words in _chunks(command):
        head = words[0].rsplit("/", 1)[-1]
        args = [w for w in words[1:] if not w.startswith("-")]
        if head == "tee":
            targets += args
        elif head in ("cp", "mv", "ln", "install") and len(args) >= 2:
            targets.append(args[-1])
    return targets


# ── the rules ────────────────────────────────────────────────────────────────

def _download_and_run(tool: str, args: dict, root: str) -> bool:
    return tool == "bash" and bool(DOWNLOAD_AND_RUN.search(args.get("command", "")))


def _secrets(tool: str, args: dict, root: str) -> bool:
    if tool == "read":
        path = args.get("path", "")
        return bool(SECRET_PATH.search(path) or DOTENV.search(path.rsplit("/", 1)[-1]))
    if tool == "write":
        return bool(SECRET_PATH.search(args.get("path", "")))
    if tool == "bash":
        cmd = args.get("command", "")
        if SECRET_PATH.search(cmd) or SECRET_ENV.search(cmd):
            return True
        return any(words[0].rsplit("/", 1)[-1] in _READERS
                   and any(DOTENV.search(w.rsplit("/", 1)[-1]) for w in words[1:])
                   for words in _chunks(cmd))
    if tool in ("grep", "glob"):
        return bool(SECRET_PATH.search(args.get("path", "") + " " + args.get("pattern", "")))
    return False


def _sends_out(tool: str, args: dict, root: str) -> bool:
    if tool != "bash":
        return False
    cmd = args.get("command", "")
    return bool(UPLOAD.search(cmd) or NET_PIPE.search(cmd) or REMOTE_COPY.search(cmd))


def _profile(path: str) -> bool:
    home = _home()
    return any(path == os.path.join(home, p) for p in PROFILES)


def _persistence(tool: str, args: dict, root: str) -> bool:
    if tool == "write":
        path = _resolve(args.get("path", ""), root)
        return (_profile(path) or "/.git/hooks/" in path + "/"
                or bool(AGENT_CONFIG.search(path)))
    if tool == "bash":
        cmd = args.get("command", "")
        if PERSIST_CMD.search(cmd):
            return True
        for target in _write_targets(cmd):
            path = _resolve(target, root)
            if _profile(path) or "/.git/hooks/" in path + "/" or AGENT_CONFIG.search(path):
                return True
    return False


def _writes_outside(tool: str, args: dict, root: str) -> bool:
    if tool == "write":
        raw = args.get("path", "")
        if not raw:
            return False
        path = _resolve(raw, root)
        return not _inside(path, root) and not _temp(path)
    if tool == "bash":
        for target in _write_targets(args.get("command", "")):
            if target.startswith("&") or target.startswith("/dev/"):
                continue
            path = _resolve(target, root)
            if path.startswith(SYSTEM_DIRS) or (not _inside(path, root) and not _temp(path)
                                                and (target.startswith(("~", "$HOME", "/", ".."))
                                                     or path.startswith(_home()))):
                return True
    return False


def _destructive(tool: str, args: dict, root: str) -> bool:
    if tool != "bash":
        return False
    cmd = args.get("command", "")
    if re.search(r"\bmkfs(?:\.\w+)?\b|\bdd\b[^\n]*\bof=/dev/", cmd):
        return True
    for words in _chunks(cmd):
        head = words[0].rsplit("/", 1)[-1]
        if head == "sudo" and len(words) > 1:
            words, head = words[1:], words[1].rsplit("/", 1)[-1]
        if head == "rm":
            flags = "".join(w.lstrip("-") for w in words[1:] if w.startswith("-") and not w.startswith("--"))
            recursive = "r" in flags.lower() or "--recursive" in words
            if not recursive:
                continue
            for target in (w for w in words[1:] if not w.startswith("-")):
                if target in ("/", "/*", "~", "~/", "~/*", "$HOME", "$HOME/", "*", ".", "./", "..", "../"):
                    return True
                path = _resolve(target, root)
                if path == _home() or path == "/" or (not _inside(path, root) and not _temp(path)):
                    return True
        if head == "git" and len(words) > 1 and words[1] == "push":
            if any(w in ("--force", "-f") or (w.startswith("-") and not w.startswith("--") and "f" in w)
                   or w.startswith("+") for w in words[2:]):
                return True
    return False


def _privilege(tool: str, args: dict, root: str) -> bool:
    if tool != "bash":
        return False
    for words in _chunks(args.get("command", "")):
        head = words[0].rsplit("/", 1)[-1]
        if head in ("sudo", "doas", "su", "pkexec"):
            return True
        if head == "chmod" and any(w in ("777", "a+rwx", "-R") for w in words[1:]) \
                and any(w.startswith(("/", "~")) for w in words[1:]):
            return True
    return False


_MATCH: dict[str, Callable[[str, dict, str], bool]] = {
    "download_and_run": _download_and_run,
    "agent_config": lambda t, a, r: (t == "write" and bool(AGENT_CONFIG.search(_resolve(a.get("path", ""), r))))
    or (t == "bash" and any(AGENT_CONFIG.search(_resolve(x, r)) for x in _write_targets(a.get("command", "")))),
    "secrets": _secrets,
    "sends_out": _sends_out,
    "persistence": _persistence,
    "writes_outside": _writes_outside,
    "destructive": _destructive,
    "privilege": _privilege,
}

RULES: dict[str, Rule] = {r.id: r for r in (
    Rule("download_and_run", "downloads code and runs it",
         "what it downloads is never seen before it runs"),
    Rule("agent_config", "changes the agent's own guard",
         "the hooks and rules that govern this agent are not the agent's to edit"),
    Rule("secrets", "reads secrets",
         "keys and tokens in the agent's context can be sent anywhere it can reach"),
    Rule("sends_out", "sends a file or data out of this machine",
         "uploads and raw network pipes are how data leaves"),
    Rule("persistence", "changes what runs later",
         "shell profiles, git hooks, cron and services outlive the session"),
    Rule("writes_outside", "writes outside the repository",
         "a coding task changes this repository, not the rest of the machine"),
    Rule("destructive", "deletes or rewrites what cannot be undone",
         "a recursive delete outside the repository, a force push, a disk write"),
    Rule("privilege", "asks for root",
         "a coding task does not need to become root"),
)}


def allowed_rules(root: str) -> set[str]:
    """Rules this workspace turned off: ``.axor/rules.json`` ``{"allow": [...]}``
    and ``AXOR_ALLOW_RULES``. An unknown id is ignored, never an error."""
    allow = {x.strip() for x in os.environ.get("AXOR_ALLOW_RULES", "").split(",") if x.strip()}
    path = Path(root) / ".axor" / "rules.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        allow |= {str(x) for x in data.get("allow", []) if isinstance(x, str)}
    except (OSError, ValueError, AttributeError):
        pass
    # the agent's own guard cannot be switched off from inside the workspace
    allow.discard("agent_config")
    return allow & set(RULES)


def check_call(tool: str, args: dict, root: str, allow: set[str] | frozenset[str] = frozenset()) -> Rule | None:
    """The first rule this canonical call breaks, or None."""
    args = {k: (v if isinstance(v, str) else str(v)) for k, v in (args or {}).items()}
    for rule_id, match in _MATCH.items():
        if rule_id in allow:
            continue
        try:
            if match(tool, args, root):
                return RULES[rule_id]
        except Exception:  # noqa: BLE001 - a rule that cannot parse a call never breaks it
            continue
    return None


def refusal(rule: Rule) -> str:
    """The reason the agent is given."""
    return (f"this call {rule.what} — {rule.why}. Refused by the axor rule "
            f"'{rule.id}'; if this repository needs it, add it to .axor/rules.json "
            f'{{"allow": ["{rule.id}"]}}.')
