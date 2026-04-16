"""Tests for boxmunge.manifest — project manifest loading and validation."""

import pytest
from pathlib import Path

from boxmunge.manifest import load_manifest, validate_manifest, ManifestError


VALID_MANIFEST = """\
id: 01TESTULID0000000000000000
source: bundle
project: myapp
repo: git@github.com:org/myapp.git
ref: main
hosts:
  - myapp.example.com
services:
  frontend:
    type: frontend
    port: 3000
    routes:
      - path: /
    smoke: boxmunge-scripts/smoke.sh
  backend:
    type: backend
    port: 8000
    internal: true
    routes:
      - path: /api/*
    health:
      endpoint: /api/health
      interval: 30s
backup:
  type: none
deploy:
  pre_deploy: ""
  snapshot_before_deploy: true
env_files:
  - project.env
"""

MINIMAL_MANIFEST = """\
id: 01TESTULID0000000000000000
source: bundle
project: tiny
repo: git@github.com:org/tiny.git
ref: main
hosts:
  - tiny.example.com
services:
  web:
    type: frontend
    port: 8080
    routes:
      - path: /
    smoke: boxmunge-scripts/smoke.sh
backup:
  type: none
env_files: []
"""


def _write_manifest(project_dir: Path, content: str) -> Path:
    project_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = project_dir / "manifest.yml"
    manifest_path.write_text(content)
    return manifest_path


class TestLoadManifest:
    def test_loads_valid_manifest(self, tmp_path: Path) -> None:
        p = tmp_path / "myapp"
        _write_manifest(p, VALID_MANIFEST)
        m = load_manifest(p / "manifest.yml")
        assert m["project"] == "myapp"
        assert m["hosts"] == ["myapp.example.com"]
        assert "frontend" in m["services"]
        assert m["services"]["backend"]["internal"] is True

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ManifestError, match="not found"):
            load_manifest(tmp_path / "nope" / "manifest.yml")


class TestValidateManifest:
    def test_valid_manifest_passes(self, tmp_path: Path) -> None:
        p = tmp_path / "myapp"
        _write_manifest(p, VALID_MANIFEST)
        m = load_manifest(p / "manifest.yml")
        errors, warnings = validate_manifest(m, "myapp")
        assert errors == []

    def test_project_name_mismatch(self, tmp_path: Path) -> None:
        p = tmp_path / "wrong"
        _write_manifest(p, VALID_MANIFEST)
        m = load_manifest(p / "manifest.yml")
        errors, warnings = validate_manifest(m, "wrong")
        assert any("project name" in e.lower() for e in errors)

    def test_missing_hosts(self, tmp_path: Path) -> None:
        content = VALID_MANIFEST.replace("hosts:\n  - myapp.example.com\n", "hosts: []\n")
        p = tmp_path / "myapp"
        _write_manifest(p, content)
        m = load_manifest(p / "manifest.yml")
        errors, warnings = validate_manifest(m, "myapp")
        assert any("hosts" in e.lower() for e in errors)

    def test_service_missing_port(self, tmp_path: Path) -> None:
        content = VALID_MANIFEST.replace("    port: 3000\n", "")
        p = tmp_path / "myapp"
        _write_manifest(p, content)
        m = load_manifest(p / "manifest.yml")
        errors, warnings = validate_manifest(m, "myapp")
        assert any("port" in e.lower() for e in errors)

    def test_service_missing_routes(self, tmp_path: Path) -> None:
        content = VALID_MANIFEST.replace(
            "    routes:\n      - path: /\n    smoke:",
            "    routes: []\n    smoke:"
        )
        p = tmp_path / "myapp"
        _write_manifest(p, content)
        m = load_manifest(p / "manifest.yml")
        errors, warnings = validate_manifest(m, "myapp")
        assert any("route" in e.lower() for e in errors)

    def test_backup_without_restore_command(self, tmp_path: Path) -> None:
        content = VALID_MANIFEST.replace(
            "  type: none",
            "  type: db-dump\n  dump_command: boxmunge-scripts/backup.sh"
        )
        p = tmp_path / "myapp"
        _write_manifest(p, content)
        m = load_manifest(p / "manifest.yml")
        errors, warnings = validate_manifest(m, "myapp")
        assert any("restore_command" in e.lower() for e in errors)

    def test_warns_if_no_smoke_test(self, tmp_path: Path) -> None:
        content = MINIMAL_MANIFEST.replace(
            "    smoke: boxmunge-scripts/smoke.sh\n",
            ""
        )
        p = tmp_path / "tiny"
        _write_manifest(p, content)
        m = load_manifest(p / "manifest.yml")
        errors, warnings = validate_manifest(m, "tiny")
        assert errors == []
        assert any("smoke" in w.lower() for w in warnings)

    def test_routes_must_be_dicts_with_path(self, tmp_path: Path) -> None:
        """Routes like ['/'] instead of [{path: '/'}] should be caught."""
        content = VALID_MANIFEST.replace(
            "    routes:\n      - path: /\n    smoke:",
            "    routes:\n      - /\n    smoke:"
        )
        p = tmp_path / "myapp"
        _write_manifest(p, content)
        m = load_manifest(p / "manifest.yml")
        errors, warnings = validate_manifest(m, "myapp")
        assert any("path" in e.lower() for e in errors)

    def test_minimal_manifest_passes(self, tmp_path: Path) -> None:
        p = tmp_path / "tiny"
        _write_manifest(p, MINIMAL_MANIFEST)
        m = load_manifest(p / "manifest.yml")
        errors, warnings = validate_manifest(m, "tiny")
        assert errors == []


class TestManifestIdAndSource:
    def test_errors_missing_id(self) -> None:
        manifest = {
            "project": "testapp",
            "hosts": ["testapp.example.com"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        errors, warnings = validate_manifest(manifest, "testapp")
        assert any("'id'" in e for e in errors)

    def test_accepts_valid_id(self) -> None:
        manifest = {
            "id": "01JQFX3M7KZYX9P5V8N2WABCDE",
            "source": "bundle",
            "project": "testapp",
            "hosts": ["testapp.example.com"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        errors, warnings = validate_manifest(manifest, "testapp")
        assert not errors
        id_warnings = [w for w in warnings if "no 'id' field" in w.lower()]
        assert not id_warnings

    def test_errors_missing_source(self) -> None:
        manifest = {
            "id": "01JQFX3M7KZYX9P5V8N2WABCDE",
            "project": "testapp",
            "hosts": ["testapp.example.com"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        errors, warnings = validate_manifest(manifest, "testapp")
        assert any("'source'" in e for e in errors)

    def test_accepts_valid_source_bundle(self) -> None:
        manifest = {
            "id": "01JQFX3M7KZYX9P5V8N2WABCDE",
            "project": "testapp",
            "source": "bundle",
            "hosts": ["testapp.example.com"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        errors, warnings = validate_manifest(manifest, "testapp")
        assert not errors

    def test_accepts_valid_source_git(self) -> None:
        manifest = {
            "id": "01JQFX3M7KZYX9P5V8N2WABCDE",
            "project": "testapp",
            "source": "git",
            "repo": "git@github.com:org/app.git",
            "ref": "main",
            "hosts": ["testapp.example.com"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        errors, warnings = validate_manifest(manifest, "testapp")
        assert not errors

    def test_errors_invalid_source(self) -> None:
        manifest = {
            "id": "01JQFX3M7KZYX9P5V8N2WABCDE",
            "project": "testapp",
            "source": "invalid",
            "hosts": ["testapp.example.com"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        errors, warnings = validate_manifest(manifest, "testapp")
        assert any("source" in e.lower() for e in errors)

    def test_git_source_requires_repo(self) -> None:
        manifest = {
            "id": "01JQFX3M7KZYX9P5V8N2WABCDE",
            "project": "testapp",
            "source": "git",
            "hosts": ["testapp.example.com"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        errors, warnings = validate_manifest(manifest, "testapp")
        assert any("repo" in e.lower() for e in errors)


class TestSchemaVersion:
    def test_no_schema_version_defaults_to_1(self) -> None:
        manifest = {
            "id": "01TEST", "project": "testapp", "source": "bundle",
            "hosts": ["testapp.example.com"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        errors, warnings = validate_manifest(manifest, "testapp")
        assert not any("schema_version" in e for e in errors)

    def test_schema_version_1_accepted(self) -> None:
        manifest = {
            "schema_version": 1,
            "id": "01TEST", "project": "testapp", "source": "bundle",
            "hosts": ["testapp.example.com"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        errors, warnings = validate_manifest(manifest, "testapp")
        assert not any("schema_version" in e for e in errors)

    def test_schema_version_zero_rejected(self) -> None:
        manifest = {
            "schema_version": 0,
            "id": "01TEST", "project": "testapp", "source": "bundle",
            "hosts": ["testapp.example.com"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        errors, warnings = validate_manifest(manifest, "testapp")
        assert any("schema_version" in e for e in errors)

    def test_unknown_schema_version_rejected(self) -> None:
        manifest = {
            "schema_version": 99,
            "id": "01TEST", "project": "testapp", "source": "bundle",
            "hosts": ["testapp.example.com"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        errors, warnings = validate_manifest(manifest, "testapp")
        assert any("schema_version" in e for e in errors)
        assert any("upgrade boxmunge" in e.lower() for e in errors)


class TestManifestResourceLimits:
    def test_warns_no_limits(self) -> None:
        manifest = {
            "id": "01TEST", "project": "testapp", "source": "bundle",
            "hosts": ["testapp.example.com"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        errors, warnings = validate_manifest(manifest, "testapp")
        assert not errors
        assert any("resource limits" in w.lower() for w in warnings)

    def test_no_warning_with_limits(self) -> None:
        manifest = {
            "id": "01TEST", "project": "testapp", "source": "bundle",
            "hosts": ["testapp.example.com"],
            "services": {"web": {
                "port": 8080, "routes": [{"path": "/"}],
                "limits": {"memory": "512m"},
            }},
        }
        errors, warnings = validate_manifest(manifest, "testapp")
        limit_warnings = [w for w in warnings if "resource limits" in w.lower()]
        assert not limit_warnings
