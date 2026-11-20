"""Which repository a coding session works in — for the team's memory, which
is kept per repository.

The id is opaque: a hash of the normalized ``origin`` remote, so the same
repository cloned by two developers (over SSH or HTTPS, with or without
``.git``) is one repository; without a remote, a hash of the checkout's path,
which only that machine shares. The label is what the Control Plane shows:
``owner/name`` from the remote, or the folder's name.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path


def _git(root: str, *args: str) -> str:
    try:
        out = subprocess.run(["git", *args], cwd=root or None, capture_output=True,
                             text=True, timeout=2)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def normalize_remote(url: str) -> str:
    """``git@github.com:Acme/API.git`` and ``https://user@github.com/acme/api``
    are the same repository: ``github.com/acme/api``."""
    u = url.strip()
    u = re.sub(r"^[a-z+]+://", "", u)            # scheme
    u = re.sub(r"^[^@/]+@", "", u)               # user@
    u = re.sub(r"^([^/:]+):(?!\d+/)", r"\1/", u)  # scp-like host:path
    u = re.sub(r":\d+/", "/", u)                 # a port
    u = re.sub(r"\.git/?$", "", u).rstrip("/")
    return u.lower()


def repo_identity(root: str) -> tuple[str, str]:
    """(opaque id, label) of the repository at ``root``."""
    remote = _git(root, "config", "--get", "remote.origin.url")
    if remote:
        norm = normalize_remote(remote)
        label = "/".join(norm.split("/")[-2:])
        return "r-" + hashlib.sha256(norm.encode()).hexdigest()[:16], label[:100]
    top = _git(root, "rev-parse", "--show-toplevel") or root or "."
    path = str(Path(top).resolve())
    return "p-" + hashlib.sha256(path.encode()).hexdigest()[:16], Path(path).name[:100]
