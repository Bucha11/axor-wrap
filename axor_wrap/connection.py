"""Where this machine's Control Plane is — set once with ``axor-wrap connect``.

``axor-wrap connect https://plane.example --key ak_…`` checks the address and
the key against the plane and keeps them in ``~/.axor/connection.json``
(readable by this user only). Every axor command on the machine reads it from
there: the hook sidecar, ``skill share`` / ``skill try``, ``tree run``,
axor-eval's ``--plane``. Nothing has to be exported in a shell profile.

``AXOR_PLANE_URL`` and ``AXOR_INGEST_KEY`` still win when set, so a CI job or a
one-off run can point somewhere else without touching the saved connection.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

ENV_URL = "AXOR_PLANE_URL"
ENV_KEY = "AXOR_INGEST_KEY"


def path() -> Path:
    home = Path(os.environ.get("HOME") or Path.home())
    return home / ".axor" / "connection.json"


def load() -> dict:
    try:
        data = json.loads(path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def plane_url() -> str | None:
    """The plane this machine reports to: the environment, else the saved one."""
    return os.environ.get(ENV_URL) or str(load().get("url") or "") or None


def ingest_key() -> str | None:
    """The key it reports with — from the same place the address came from, so
    an address from the environment never pairs with a saved key for another
    plane."""
    if os.environ.get(ENV_URL):
        return os.environ.get(ENV_KEY) or None
    return os.environ.get(ENV_KEY) or str(load().get("key") or "") or None


def saved_key(url: str) -> str | None:
    """The key saved for this same plane: reconnecting without --key (to add
    operator keys) keeps it."""
    old = load()
    return str(old.get("key") or "") or None if old.get("url") == url.rstrip("/") else None


def save(url: str, key: str | None, *, operator_keys: dict[str, str] | None = None) -> Path:
    """Keep the plane, its key and — when given — the operators' public keys
    (axor_wrap.agents.signed). Reconnecting to the same plane without them
    keeps what was saved: a key is taken away only by disconnecting."""
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    old = load()
    keep = old.get("operator_keys") if old.get("url") == url.rstrip("/") else None
    data: dict = {"url": url.rstrip("/"), "key": key or saved_key(url) or ""}
    if operator_keys or keep:
        data["operator_keys"] = operator_keys or keep
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, p)
    return p


def clear() -> bool:
    try:
        path().unlink()
    except FileNotFoundError:
        return False
    return True


class ConnectError(Exception):
    """The plane could not be reached, or refused the key."""


def check(url: str, key: str | None, *, timeout: float = 10.0) -> None:
    """Ask the plane what a connected agent asks first (its coding policy).
    Raises ConnectError with a sentence a person can act on."""
    req = urllib.request.Request(f"{url.rstrip('/')}/v1/coding/policy")
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - the user's own plane
            resp.read(1)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise ConnectError("the plane refused this key — create a new one on its Connect page") from exc
        raise ConnectError(f"the plane answered {exc.code} — is {url} a Control Plane?") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ConnectError(f"cannot reach {url}: {getattr(exc, 'reason', exc)}") from exc
