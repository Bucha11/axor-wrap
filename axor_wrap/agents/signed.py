"""What the sidecar believes of the Control Plane once it has operator keys.

With no operator keys in this machine's config (the open posture) the sidecar
takes the plane's word, as before. With them (``axor-wrap connect
--operator-key op=HEX`` or ``AXOR_OPERATOR_KEYS``), the plane is a messenger:

* **what narrows is taken unsigned** — a skill turned off, the team's brake, a
  pause or stop (those are verified as commands by the plane link already).
  A compromised plane can at worst withhold one, which it could do anyway;
* **what widens needs an operator's signature** — the team's rules (what they
  allow, observe mode, exceptions, trusted sources) and the skills turned on
  for the team come only from the last policy an operator signed, never an
  older one, and a skill's files must hash to what that policy names;
* **what goes into the agent's context unsigned is outside text** — the team's
  memory, a note, another agent's message: given, but registered as untrusted,
  so a command built from it is refused like one built from a web page. A note
  an operator signed is the developer's words, as before.

Keys come only from LOCAL config, never over the channel.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

ENV_KEYS = "AXOR_OPERATOR_KEYS"


def operator_keys() -> dict[str, str]:
    """``{operator: ed25519 public key hex}`` — the environment, else the
    saved connection."""
    raw = os.environ.get(ENV_KEYS)
    if raw:
        try:
            value = json.loads(raw)
        except ValueError:
            value = None
        if isinstance(value, dict):
            return {str(k): str(v) for k, v in value.items()}
        # unreadable: never a silent fall to the open posture — the saved keys
        import logging

        logging.getLogger("axor.wrap.agents.signed").warning(
            "%s is not a JSON object of operator keys — using the saved ones", ENV_KEYS)
    from axor_wrap import connection

    saved = connection.load().get("operator_keys")
    return {str(k): str(v) for k, v in saved.items()} if isinstance(saved, dict) else {}


def _canonical(value: Any) -> bytes:  # noqa: ANN401
    from axor_core.kernel.jcs import canonicalize

    return canonicalize(value)


def verify(keys: dict[str, str], statement: Any) -> dict | None:  # noqa: ANN401
    """The signed payload of ``{"payload", "operator", "sig"}`` when an
    operator in ``keys`` signed exactly it; else None."""
    if not keys or not isinstance(statement, dict):
        return None
    payload, operator, sig = (statement.get("payload"), statement.get("operator"),
                              statement.get("sig"))
    pubkey = keys.get(str(operator)) if operator else None
    if not isinstance(payload, dict) or not pubkey or not isinstance(sig, str):
        return None
    from axor_wrap.plane.session import _verify_ed25519

    try:
        message = _canonical(payload)
    except Exception:  # noqa: BLE001 - a payload JCS refuses is not signed
        return None
    return payload if _verify_ed25519(pubkey, message, sig) else None


def bundle_digest(files: list[dict]) -> str:
    """What a team skill's files hash to — the value a signed policy names.
    The backend computes the same (axor_backend.routers.coding_api)."""
    rows = sorted(({"path": str(f.get("path", "")), "content": str(f.get("content", ""))}
                   for f in files if isinstance(f, dict)), key=lambda f: f["path"])
    return hashlib.sha256(_canonical({"files": rows})).hexdigest()


def trusted_policy(keys: dict[str, str], policy: dict | None,
                   min_seq: int) -> tuple[dict | None, int, bool]:
    """``(policy to apply, newest signed seq, whether its widening part was
    signed)``. What narrows passes through; rules and team skills come only
    from a signed document at least as new as ``min_seq``."""
    if not isinstance(policy, dict):
        return policy, min_seq, False
    out: dict = {k: policy[k] for k in ("skills_off", "brake") if k in policy}
    doc = verify(keys, policy.get("signed"))
    if doc is not None and doc.get("kind") == "coding_policy" \
            and isinstance(doc.get("seq"), int) and doc["seq"] >= min_seq:
        if isinstance(doc.get("rules"), dict):
            out["rules"] = doc["rules"]
        out["skills_team"] = [s for s in doc.get("skills_team") or [] if isinstance(s, dict)]
        return out, doc["seq"], True
    # nothing signed (or older than what was seen): no rule relaxed, no
    # team skill installed — and any installed one removed
    out["skills_team"] = []
    return out, min_seq, False


def signed_note(keys: dict[str, str], note: dict, node_id: str) -> bool:
    """Whether an operator signed exactly this note, to this session."""
    payload = verify(keys, note.get("signed"))
    return bool(payload) and payload.get("kind") == "note" \
        and payload.get("node_id") == node_id and payload.get("text") == note.get("text")


def fingerprint(keys: dict[str, str]) -> str:
    """A short digest of a keyset to compare by eye — the same the plane's
    Connect page shows (axor_backend.signing.fingerprint)."""
    if not keys:
        return ""
    line = "\n".join(sorted(f"{op}={str(k).lower()}" for op, k in keys.items()))
    digest = hashlib.sha256(line.encode()).hexdigest()[:16]
    return " ".join(digest[i:i + 4] for i in range(0, 16, 4))


def apply_operators(roots: dict[str, str], operators: Any,  # noqa: ANN401
                    revoked: set[str]) -> dict[str, str]:
    """The keys to trust now: the ROOTS (this machine's own config) and every
    key the plane lists that a trusted key vouched for, worked out from the
    roots each time — so revoking a key also drops every key trusted only
    through it. Revoked keys (the plane's word; it only narrows) accumulate in
    ``revoked`` and are never trusted again, roots included."""
    if isinstance(operators, dict):
        revoked.update(str(r) for r in operators.get("revoked") or [])
        listed = [e for e in operators.get("endorsed") or [] if isinstance(e, dict)]
    else:
        listed = []
    out = {k: v for k, v in roots.items() if k not in revoked}
    grew = True
    while grew:
        grew = False
        for e in listed:
            op, pubkey = str(e.get("operator", "")), str(e.get("pubkey", "")).lower()
            if op in out or op in revoked:
                continue
            endorsement = e.get("endorsement")
            payload = verify(out, endorsement)
            if payload and payload.get("kind") == "operator_key" \
                    and payload.get("operator") == op and payload.get("pubkey") == pubkey:
                out[op] = pubkey
                grew = True
    return out
