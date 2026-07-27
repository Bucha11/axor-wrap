from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from axor_wrap.cli import main

from tests import fixtures


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class CliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.write_project(fixtures.ALL_FIXTURES)
        self.out_dir = Path(tempfile.mkdtemp(prefix="axor_wrap_out_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.out_dir, ignore_errors=True)

    def test_scan_prints_table(self) -> None:
        code, out, _ = run_cli(["scan", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("TOOL", out)
        self.assertIn("send_email", out)
        self.assertIn("EXPORT", out)
        self.assertIn("shell", out)
        self.assertIn("tool(s) detected", out)

    def test_scan_empty_project_exits_2(self) -> None:
        empty = fixtures.write_project({"plain.py": fixtures.NO_TOOLS})
        try:
            code, _, err = run_cli(["scan", str(empty)])
            self.assertEqual(code, 2)
            self.assertIn("no tools detected", err)
        finally:
            shutil.rmtree(empty, ignore_errors=True)

    def test_scan_missing_path_exits_2(self) -> None:
        code, _, err = run_cli(["scan", str(self.root / "nope")])
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)

    def test_manifest_writes_files_and_sidecar(self) -> None:
        code, out, _ = run_cli(["manifest", str(self.root), "-o", str(self.out_dir)])
        self.assertEqual(code, 0)
        manifest_path = self.out_dir / "send_email.manifest.json"
        self.assertTrue(manifest_path.exists())
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(manifest["schema_version"], "tool-manifest/v1")
        self.assertEqual(manifest["effect"]["default_class"], "EXPORT")

        wrap = json.loads((self.out_dir / "wrap.json").read_text())
        by_id = {t["id"]: t for t in wrap["tools"]}
        self.assertIn("send_email", by_id)
        # UNKNOWN survives honestly in the sidecar even though the manifest says EXEC
        self.assertEqual(by_id["mystery_gizmo"]["effect_guess"]["class"], "UNKNOWN")
        gizmo = json.loads((self.out_dir / "mystery_gizmo.manifest.json").read_text())
        self.assertEqual(gizmo["effect"]["default_class"], "EXEC")

    def test_config_prints_yaml_from_manifests_dir(self) -> None:
        code, _, _ = run_cli(["manifest", str(self.root), "-o", str(self.out_dir)])
        self.assertEqual(code, 0)
        code, out, _ = run_cli(["config", str(self.out_dir)])
        self.assertEqual(code, 0)
        self.assertIn("egress_sinks:", out)
        self.assertIn('"send_email"', out)
        self.assertIn("untrusted_sources:", out)

    def test_config_empty_dir_exits_2(self) -> None:
        code, _, err = run_cli(["config", str(self.out_dir)])
        self.assertEqual(code, 2)
        self.assertIn("no tool-manifest/v1 manifests", err)

    def test_connect_lab_unreachable_exits_2(self) -> None:
        code, _, err = run_cli([
            "connect-lab", "--base-url", "http://127.0.0.1:1", "--model", "m",
        ])
        self.assertEqual(code, 2)
        self.assertIn("error:", err)


if __name__ == "__main__":
    unittest.main()
