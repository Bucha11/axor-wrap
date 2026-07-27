from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

import axor_wrap


class VersionTest(unittest.TestCase):
    def test_runtime_version_matches_pyproject(self) -> None:
        root = next(p for p in Path(__file__).resolve().parents
                    if (p / "pyproject.toml").exists())
        data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(axor_wrap.__version__, data["project"]["version"])


if __name__ == "__main__":
    unittest.main()
