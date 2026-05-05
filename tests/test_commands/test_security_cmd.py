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
