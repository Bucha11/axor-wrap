from __future__ import annotations

import unittest

from axor_wrap.detect import DetectedTool
from axor_wrap.errors import ManifestValidationError
from axor_wrap.manifest import build_manifest, embedded_schema, ensure_valid, validate_manifest
from axor_wrap.roles import EffectGuess


def make_tool(tool_id: str = "send_email", description: str = "Send an email") -> DetectedTool:
    return DetectedTool(
        id=tool_id, source="a.py:1 test", description=description,
        args_schema={"type": "object", "properties": {"to": {"type": "string"}},
                     "required": ["to"]},
    )


class ManifestTest(unittest.TestCase):
    def test_built_manifest_is_valid(self) -> None:
        guess = EffectGuess("EXPORT", "high", "test", driving_args=("to",))
        manifest = build_manifest(make_tool(), guess)
        self.assertEqual(validate_manifest(manifest), [])
        self.assertEqual(manifest["schema_version"], "tool-manifest/v1")
        self.assertEqual(manifest["id"], "send_email")
        self.assertEqual(manifest["effect"]["default_class"], "EXPORT")
        self.assertEqual(manifest["effect"]["driving_args"], ["to"])

    def test_side_effecting_flag(self) -> None:
        for cls, expected in (("READ", False), ("WRITE", True), ("EXPORT", True),
                              ("EXEC", True), ("UNKNOWN", True)):
            manifest = build_manifest(make_tool(), EffectGuess(cls, "low", "t"))
            self.assertEqual(manifest["side_effecting"], expected, cls)
            self.assertEqual(validate_manifest(manifest), [], cls)

    def test_unknown_compiles_fail_closed_to_exec(self) -> None:
        manifest = build_manifest(make_tool(), EffectGuess("UNKNOWN", "low", "t"))
        # the schema enum has no UNKNOWN; fail-closed → EXEC (egress-gated)
        self.assertEqual(manifest["effect"]["default_class"], "EXEC")
        self.assertEqual(validate_manifest(manifest), [])

    def test_untrusted_fields_carried(self) -> None:
        guess = EffectGuess("READ", "high", "t", untrusted_fields=("result.*",))
        manifest = build_manifest(make_tool("search_web", "Search"), guess)
        self.assertEqual(manifest["untrusted_fields"], ["result.*"])
        self.assertEqual(validate_manifest(manifest), [])

    def test_description_lands_in_args_schema_annotation(self) -> None:
        manifest = build_manifest(make_tool(), EffectGuess("EXPORT", "high", "t"))
        self.assertEqual(manifest["args_schema"]["description"], "Send an email")

    def test_validator_rejects_bad_manifests(self) -> None:
        self.assertTrue(validate_manifest({"schema_version": "tool-manifest/v1"}))  # missing req
        self.assertTrue(validate_manifest({
            "schema_version": "tool-manifest/v2", "id": "x", "args_schema": {},
            "effect": {"default_class": "READ", "driving_args": []}, "side_effecting": False,
        }))  # const mismatch
        self.assertTrue(validate_manifest({
            "schema_version": "tool-manifest/v1", "id": "x", "args_schema": {},
            "effect": {"default_class": "UNKNOWN", "driving_args": []}, "side_effecting": True,
        }))  # UNKNOWN not in the effect enum
        self.assertTrue(validate_manifest({
            "schema_version": "tool-manifest/v1", "id": "x", "args_schema": {},
            "effect": {"default_class": "READ", "driving_args": []},
            "side_effecting": False, "surprise": 1,
        }))  # additionalProperties: false

    def test_ensure_valid_raises_with_tool_id(self) -> None:
        good = build_manifest(make_tool(), EffectGuess("EXPORT", "high", "t"))
        self.assertIs(ensure_valid(good), good)
        with self.assertRaises(ManifestValidationError) as ctx:
            ensure_valid({"schema_version": "tool-manifest/v1", "id": "broken"})
        self.assertEqual(ctx.exception.tool_id, "broken")
        self.assertTrue(ctx.exception.errors)

    def test_embedded_schema_is_the_lab_contract(self) -> None:
        schema = embedded_schema()
        self.assertEqual(schema["properties"]["schema_version"]["const"], "tool-manifest/v1")
        self.assertIn("effect", schema["required"])


if __name__ == "__main__":
    unittest.main()
