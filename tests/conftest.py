"""No test reads or writes the real machine's Control-Plane connection."""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_connection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from axor_wrap import connection

    monkeypatch.setattr(connection, "path", lambda: tmp_path / ".axor" / "connection.json")
