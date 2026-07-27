"""Effect-role inference — honest heuristics over detected tools.

``infer_effect`` guesses each tool's consequence class (READ / WRITE / EXPORT /
EXEC) from its name, description and argument names. **UNKNOWN is a normal
outcome**: the final classification is a human decision in the config builder
(same flow as the Control Plane) — the heuristic never pretends to certainty it
does not have, which is why every guess carries a confidence and a reason.

Also guessed:

- ``driving_args`` — the carrier arguments whose provenance the gate checks
  (to / recipient / url / channel / path / command, ...);
- ``untrusted_fields`` — for reads that ingest external content (web, search,
  fetch, inbox, ...) the coarse ``result.*`` taint candidate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from axor_wrap.detect import DetectedTool

READ = "READ"
WRITE = "WRITE"
EXPORT = "EXPORT"
EXEC = "EXEC"
UNKNOWN = "UNKNOWN"

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

_EXEC_TOKENS = frozenset({
    "shell", "exec", "execute", "run", "eval", "bash", "sh", "subprocess",
    "command", "cmd", "terminal", "spawn",
})
_EXPORT_TOKENS = frozenset({
    # NB: deliberately no bare "email"/"mail" — read_email must stay a READ;
    # the export verb (send/post/forward/...) carries the signal.
    "send", "post", "publish", "upload", "slack", "notify",
    "tweet", "share", "broadcast", "submit", "transfer", "pay", "sms", "dm",
    "forward", "reply",
})
_WRITE_TOKENS = frozenset({
    "write", "update", "create", "insert", "delete", "remove", "set", "save",
    "edit", "append", "add", "move", "rename", "mkdir", "put", "patch",
})
_READ_TOKENS = frozenset({
    "read", "get", "search", "list", "fetch", "find", "load", "lookup", "view",
    "browse", "scrape", "download", "query", "inbox", "check", "ls", "cat",
    "crawl", "retrieve",
})
_SQL_TOKENS = frozenset({"sql", "query", "db", "database"})
_SQL_WRITE_TOKENS = frozenset({"insert", "update", "delete", "drop", "alter", "write"})

# carrier arguments, in preference order (the first one becomes the allowlist arg)
_DRIVING_ARG_ORDER = (
    "to", "recipient", "recipients", "url", "channel", "path", "command", "cmd",
    "address", "destination", "target", "email", "file_path",
)
# argument names that raise EXPORT confidence: they carry a destination
_EXPORT_CARRIER_ARGS = frozenset({
    "to", "recipient", "recipients", "channel", "url", "address", "destination", "email",
})
_UNTRUSTED_HINTS = frozenset({
    "web", "search", "fetch", "http", "https", "browse", "scrape", "inbox",
    "mail", "email", "download", "crawl", "url", "feed", "news", "messages", "page",
})
_COARSE_UNTRUSTED_FIELD = "result.*"  # coarse whole-result fallback, field-level is human work


@dataclass(frozen=True)
class EffectGuess:
    """A heuristic effect classification, with its confidence and rationale."""

    default_class: str  # READ | WRITE | EXPORT | EXEC | UNKNOWN
    confidence: str     # high | medium | low
    reason: str
    driving_args: tuple[str, ...] = ()
    untrusted_fields: tuple[str, ...] = ()


def infer_effect(tool: DetectedTool) -> EffectGuess:
    """Guess the effect class of a detected tool. UNKNOWN when nothing matches."""
    name_tokens = _tokens(tool.id)
    desc_tokens = _tokens(tool.description)
    arg_names = _arg_names(tool)
    driving = tuple(a for a in _DRIVING_ARG_ORDER if a in arg_names)

    if tool.framework == "implicit" and tool.id == "shell":
        return EffectGuess(EXEC, CONFIDENCE_HIGH, "implicit subprocess/os.system usage",
                           driving_args=driving or ("command",))

    guess = _classify(name_tokens, desc_tokens, arg_names, source="name")
    if guess is None:
        guess = _classify(desc_tokens, desc_tokens, arg_names, source="description")
        if guess is not None:
            # description-only evidence is weaker
            cls, confidence, reason = guess
            confidence = CONFIDENCE_MEDIUM if confidence == CONFIDENCE_HIGH else CONFIDENCE_LOW
            guess = (cls, confidence, reason)
    if guess is None:
        return EffectGuess(
            UNKNOWN, CONFIDENCE_LOW,
            "no heuristic matched — classify manually in the config builder",
            driving_args=driving,
        )
    cls, confidence, reason = guess
    untrusted: tuple[str, ...] = ()
    if cls == READ and ((name_tokens | desc_tokens) & _UNTRUSTED_HINTS):
        untrusted = (_COARSE_UNTRUSTED_FIELD,)
    return EffectGuess(cls, confidence, reason, driving_args=driving, untrusted_fields=untrusted)


def _classify(
    tokens: set[str], desc_tokens: set[str], arg_names: tuple[str, ...], source: str,
) -> tuple[str, str, str] | None:
    """Ordered heuristics; returns (class, confidence, reason) or None."""
    hit = tokens & _EXEC_TOKENS
    if hit:
        return EXEC, CONFIDENCE_HIGH, f"{source} token {sorted(hit)[0]!r} → EXEC"
    if (tokens & _SQL_TOKENS) and ((tokens | desc_tokens) & _SQL_WRITE_TOKENS):
        return EXEC, CONFIDENCE_MEDIUM, f"{source} suggests SQL with write verbs → EXEC"
    hit = tokens & _EXPORT_TOKENS
    if hit:
        carriers = set(arg_names) & _EXPORT_CARRIER_ARGS
        if carriers:
            return (EXPORT, CONFIDENCE_HIGH,
                    f"{source} token {sorted(hit)[0]!r} + carrier arg {sorted(carriers)[0]!r} → EXPORT")
        return EXPORT, CONFIDENCE_MEDIUM, f"{source} token {sorted(hit)[0]!r} → EXPORT"
    hit = tokens & _WRITE_TOKENS
    if hit:
        return WRITE, CONFIDENCE_HIGH, f"{source} token {sorted(hit)[0]!r} → WRITE"
    hit = tokens & _READ_TOKENS
    if hit:
        return READ, CONFIDENCE_HIGH, f"{source} token {sorted(hit)[0]!r} → READ"
    return None


def _tokens(text: str) -> set[str]:
    # split snake_case / camelCase / words into lowercase tokens
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    return {t.lower() for t in re.split(r"[^A-Za-z]+", spaced) if t}


def _arg_names(tool: DetectedTool) -> tuple[str, ...]:
    properties = tool.args_schema.get("properties")
    if isinstance(properties, dict):
        return tuple(str(k) for k in properties)
    return ()
