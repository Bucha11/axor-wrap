"""`axor-wrap connect`: the machine's Control Plane, saved once, read by every command."""
from __future__ import annotations

import http.server
import stat
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from axor_wrap import connection
from axor_wrap.cli import main


@pytest.fixture(autouse=True)
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("AXOR_PLANE_URL", raising=False)
    monkeypatch.delenv("AXOR_INGEST_KEY", raising=False)
    return tmp_path


@pytest.fixture
def plane() -> Iterator[str]:
    """A plane that accepts the key `good` and refuses any other."""

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            ok = self.path == "/v1/coding/policy" and self.headers.get("Authorization") == "Bearer good"
            self.send_response(200 if ok else 401)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a: object) -> None:
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_saved_once_read_everywhere(home: Path) -> None:
    assert connection.plane_url() is None
    p = connection.save("https://plane.example/", "ak_1")
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert connection.plane_url() == "https://plane.example"
    assert connection.ingest_key() == "ak_1"


def test_the_environment_wins_and_never_pairs_with_another_planes_key(monkeypatch: pytest.MonkeyPatch) -> None:
    connection.save("https://plane.example", "ak_saved")
    monkeypatch.setenv("AXOR_PLANE_URL", "https://other.example")
    assert connection.plane_url() == "https://other.example"
    assert connection.ingest_key() is None


def test_connect_checks_the_key_before_saving(plane: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["connect", plane, "--key", "bad"]) != 0
    assert "refused this key" in capsys.readouterr().err
    assert connection.plane_url() is None
    assert main(["connect", plane, "--key", "good"]) == 0
    assert connection.plane_url() == plane and connection.ingest_key() == "good"
    assert main(["connect"]) == 0
    assert f"connected to {plane}" in capsys.readouterr().out
    assert main(["disconnect"]) == 0
    assert connection.plane_url() is None


def test_an_unreachable_plane_is_said_so(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["connect", "http://127.0.0.1:9", "--key", "x"]) != 0
    assert "cannot reach" in capsys.readouterr().err


def test_the_sidecar_reports_to_the_saved_plane(home: Path) -> None:
    from axor_wrap.agents.sidecar import Sidecar

    connection.save("https://plane.example", "ak_1")
    assert Sidecar(str(home), enforce=True, link_factory=lambda n: None).plane_url == "https://plane.example"


def test_a_link_takes_the_saved_key_only_for_its_own_plane() -> None:
    from axor_wrap.plane.link import _saved_key

    connection.save("https://plane.example", "ak_1")
    assert _saved_key("https://plane.example/") == "ak_1"
    assert _saved_key("https://elsewhere.example") is None


def test_sharing_a_skill_unconnected_says_how_to_connect(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    skill = home / "s"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: s\ndescription: d\n---\nhi\n")
    assert main(["skill", "share", str(skill)]) != 0
    assert "axor-wrap connect" in capsys.readouterr().err
