"""Tool-manifest building and validation (``tool-manifest/v1``).

``build_manifest`` turns a (DetectedTool, EffectGuess) pair into a manifest that
validates against the embedded schema — a verbatim copy of
``axor-lab/contracts/schemas/tool-manifest.schema.json`` (the axor-lab contracts
are the source of truth; see ``axor_wrap/schemas/``).

Two honest deviations, both fail-closed:

- the schema's effect enum has no UNKNOWN, so an UNKNOWN guess compiles to
  ``EXEC`` — the most consequential class — and the tool lands in
  ``egress_sinks`` until a human classifies it (the real guess survives in the
  ``wrap.json`` sidecar the CLI writes);
- ``side_effecting`` is true for everything except a confident READ.

``validate_manifest`` checks a manifest with a minimal own subset validator
(const / enum / type / required / properties / additionalProperties / items /
local ``#/$defs`` refs) — the same approach as axor-lab's
``lab_contracts/subset_validator.py``; the ``jsonschema`` package is deliberately
not pulled in. External refs (``predicate.schema.json``) are skipped: this
package never generates ``effect.resolve`` rules.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from axor_wrap.detect import DetectedTool
from axor_wrap.roles import EffectGuess

SCHEMA_VERSION = "tool-manifest/v1"
EFFECT_CLASSES = frozenset({"READ", "WRITE", "EXPORT", "EXEC"})
_UNKNOWN_FALLBACK = "EXEC"  # fail-closed: unclassified → most consequential

_TYPE_MAP: dict[str, type | tuple[type, ...]] = {
    "object": dict,
    "array": list,
    "string": str,
    "number": (int, float),
    "integer": int,
    "boolean": bool,
}


@lru_cache(maxsize=1)
def embedded_schema() -> dict[str, object]:
    """The embedded tool-manifest/v1 schema (copied from axor-lab contracts)."""
    path = Path(__file__).resolve().parent / "schemas" / "tool-manifest.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def build_manifest(tool: DetectedTool, effect: EffectGuess) -> dict[str, object]:
    """Compile one detected tool + effect guess into a valid tool-manifest/v1."""
    default_class = effect.default_class if effect.default_class in EFFECT_CLASSES \
        else _UNKNOWN_FALLBACK
    args_schema: dict[str, object] = dict(tool.args_schema) or {"type": "object"}
    if tool.description and "description" not in args_schema:
        # the manifest schema has no description property; the JSON-Schema
        # annotation keyword on args_schema carries it without breaking validation
        args_schema["description"] = tool.description
    manifest: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "id": tool.id,
        "args_schema": args_schema,
        "effect": {
            "default_class": default_class,
            "driving_args": list(effect.driving_args),
        },
        "side_effecting": default_class != "READ",
    }
    if effect.untrusted_fields:
        manifest["untrusted_fields"] = list(effect.untrusted_fields)
    return manifest


def validate_manifest(manifest: object) -> list[str]:
    """Validate against the embedded schema; returns the error list (empty = valid)."""
    errors: list[str] = []
    schema = embedded_schema()
    _check(manifest, schema, "$", schema, errors)
    return errors


def ensure_valid(manifest: dict[str, object]) -> dict[str, object]:
    """``validate_manifest`` that raises ``ManifestValidationError``; returns the manifest."""
    errors = validate_manifest(manifest)
    if errors:
        from axor_wrap.errors import ManifestValidationError

        raise ManifestValidationError(str(manifest.get("id")), errors)
    return manifest


# ── minimal subset validator (const/enum/type/required/properties/items/$defs) ──


def _check(
    node: object,
    schema: dict[str, object],
    path: str,
    root: dict[str, object],
    errors: list[str],
) -> None:
    if "$ref" in schema:
        ref = str(schema["$ref"])
        if ref.startswith("#/$defs/"):
            defs: dict[str, dict[str, object]] = root.get("$defs", {})  # type: ignore[assignment]
            target = defs.get(ref.rsplit("/", 1)[-1])
            if target is None:
                errors.append(f"{path}: unresolvable local $ref {ref}")
                return
            _check(node, target, path, root, errors)
            return
        return  # external ref (predicate.schema.json) — out of this package's subset

    if "const" in schema and node != schema["const"]:
        errors.append(f"{path}: const mismatch: want {schema['const']!r} got {node!r}")
    if "enum" in schema and node not in schema["enum"]:  # type: ignore[operator]
        errors.append(f"{path}: not in enum {schema['enum']}: {node!r}")

    declared = schema.get("type")
    if declared:
        types = declared if isinstance(declared, list) else [declared]
        if not any(_is_type(node, str(t)) for t in types):
            errors.append(f"{path}: type {declared}, got {type(node).__name__}")
            return
    if "pattern" in schema and isinstance(node, str):
        if not re.search(str(schema["pattern"]), node):
            errors.append(f"{path}: pattern {schema['pattern']} no match")

    if isinstance(node, dict):
        for required in schema.get("required", []):  # type: ignore[union-attr]
            if required not in node:
                errors.append(f"{path}: missing required '{required}'")
        if schema.get("type") == "object" or "properties" in schema:
            props: dict[str, dict[str, object]] = schema.get("properties", {})  # type: ignore[assignment]
            additional = schema.get("additionalProperties", True)
            for key, value in node.items():
                if key in props:
                    _check(value, props[key], f"{path}.{key}", root, errors)
                elif additional is False:
                    errors.append(f"{path}: additional property '{key}' not allowed")
                elif isinstance(additional, dict):
                    _check(value, additional, f"{path}.{key}", root, errors)

    if isinstance(node, list) and "items" in schema:
        for i, item in enumerate(node):
            _check(item, schema["items"], f"{path}[{i}]", root, errors)  # type: ignore[arg-type]


def _is_type(node: object, type_name: str) -> bool:
    if type_name == "null":
        return node is None
    expected = _TYPE_MAP.get(type_name)
    if expected is None:
        return False  # unknown type name never matches (fail closed)
    if type_name in ("number", "integer") and isinstance(node, bool):
        return False  # bool is an int subclass in Python; not a number here
    return isinstance(node, expected)
