"""Tests for the `boxmunge security <project>` introspection command."""
import io
import json
from contextlib import redirect_stdout

import pytest
import yaml

from boxmunge.commands.security_cmd import cmd_security


@pytest.fixture
def project_with_default(tmp_path, monkeypatch):
    proj = tmp_path / "projects" / "demo"
    proj.mkdir(parents=True)
    manifest = {
        "schema_version": 2,
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle",
        "project": "demo",
        "hosts": ["demo.example.com"],
        "services": {
            "web": {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"},
        },
    }
    (proj / "manifest.yml").write_text(yaml.safe_dump(manifest))
    from boxmunge.paths import BoxPaths
    monkeypatch.setattr(BoxPaths, "__init__", lambda self: None)
    paths = BoxPaths()
    paths.projects = tmp_path / "projects"
    paths.project_dir = lambda name: tmp_path / "projects" / name
    paths.project_manifest = lambda name: tmp_path / "projects" / name / "manifest.yml"
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)
    return paths


def test_security_default_lists_full_payload(project_with_default) -> None:
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["demo"])
    out = buf.getvalue()
    assert "demo" in out
    assert "schema_version: 2" in out
    assert "service: web" in out
    assert "no-new-privileges:true" in out
    assert "pids_limit" in out and "512" in out
    assert "NET_ADMIN" in out


def test_security_json_returns_structured_data(project_with_default) -> None:
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["demo", "--json"])
    payload = json.loads(buf.getvalue())
    assert payload["project"] == "demo"
    assert payload["project_profile"] == "default"
    assert "web" in payload["services"]
    web = payload["services"]["web"]
    assert web["pids_limit"] == 512
    assert "NET_ADMIN" in web["cap_drop"]
    assert payload["off_services"] == []


def test_security_json_flag_first(project_with_default) -> None:
    """Audit H-3b: ``--json`` must be detected even when it precedes the project."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["--json", "demo"])
    payload = json.loads(buf.getvalue())
    assert payload["project"] == "demo"


def test_security_text_missing_schema_version_fails_loud(monkeypatch, tmp_path, capsys) -> None:
    """Audit I-2c: a manifest missing schema_version must NOT silently default
    to 1 — operators get a clear error on stderr and exit 1."""
    proj = tmp_path / "projects" / "demo"
    proj.mkdir(parents=True)
    manifest = {
        # schema_version intentionally omitted
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle",
        "project": "demo",
        "hosts": ["demo.example.com"],
        "services": {
            "web": {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"},
        },
    }
    (proj / "manifest.yml").write_text(yaml.safe_dump(manifest))
    from boxmunge.paths import BoxPaths
    monkeypatch.setattr(BoxPaths, "__init__", lambda self: None)
    paths = BoxPaths()
    paths.projects = tmp_path / "projects"
    paths.project_dir = lambda name: tmp_path / "projects" / name
    paths.project_manifest = lambda name: tmp_path / "projects" / name / "manifest.yml"
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)
    # Bypass load_manifest's own schema validation so we can exercise the
    # security_cmd fail-loud path directly with a hand-edited manifest.
    monkeypatch.setattr(
        "boxmunge.commands.security_cmd.load_manifest",
        lambda path: manifest,
    )

    with pytest.raises(SystemExit) as exc:
        cmd_security(["demo"])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "schema_version" in captured.err
    assert "ERROR" in captured.err


def test_security_json_missing_schema_version_fails_loud(monkeypatch, tmp_path, capsys) -> None:
    """Same fail-loud guarantee for the --json code path."""
    proj = tmp_path / "projects" / "demo"
    proj.mkdir(parents=True)
    manifest = {
        # schema_version intentionally omitted
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle",
        "project": "demo",
        "hosts": ["demo.example.com"],
        "services": {
            "web": {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"},
        },
    }
    (proj / "manifest.yml").write_text(yaml.safe_dump(manifest))
    from boxmunge.paths import BoxPaths
    monkeypatch.setattr(BoxPaths, "__init__", lambda self: None)
    paths = BoxPaths()
    paths.projects = tmp_path / "projects"
    paths.project_dir = lambda name: tmp_path / "projects" / name
    paths.project_manifest = lambda name: tmp_path / "projects" / name / "manifest.yml"
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)
    monkeypatch.setattr(
        "boxmunge.commands.security_cmd.load_manifest",
        lambda path: manifest,
    )

    with pytest.raises(SystemExit) as exc:
        cmd_security(["demo", "--json"])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "schema_version" in captured.err
    assert "ERROR" in captured.err


def test_security_json_off_services(monkeypatch, tmp_path) -> None:
    proj = tmp_path / "projects" / "demo"
    proj.mkdir(parents=True)
    manifest = {
        "schema_version": 2,
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle",
        "project": "demo",
        "hosts": ["demo.example.com"],
        "security": {"profile": "off", "reason": "deliberate"},
        "services": {
            "web": {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"},
        },
    }
    (proj / "manifest.yml").write_text(yaml.safe_dump(manifest))
    from boxmunge.paths import BoxPaths
    monkeypatch.setattr(BoxPaths, "__init__", lambda self: None)
    paths = BoxPaths()
    paths.projects = tmp_path / "projects"
    paths.project_dir = lambda name: tmp_path / "projects" / name
    paths.project_manifest = lambda name: tmp_path / "projects" / name / "manifest.yml"
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)

    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["demo", "--json"])
    payload = json.loads(buf.getvalue())
    assert payload["project_profile"] == "off"
    assert payload["off_services"] == [{"service": "web", "reason": "deliberate"}]
    assert payload["services"]["web"] == {}


def test_security_unknown_flag_exits_2(capsys) -> None:
    """Audit H-N1: cmd_security rejects unknown flags."""
    with pytest.raises(SystemExit) as exc:
        cmd_security(["demo", "--not-a-flag"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "ERROR" in err
    assert "--not-a-flag" in err
