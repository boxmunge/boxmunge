"""Tests for boxmunge.manifest — project manifest loading and validation."""

import pytest
from pathlib import Path

from boxmunge.manifest import (
    CURRENT_SCHEMA_VERSION,
    ManifestError,
    load_manifest,
    validate_manifest,
)


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


class TestStagingValidation:
    def _base_manifest(self) -> dict:
        return {
            "id": "01ABC",
            "source": "bundle",
            "project": "myapp",
            "hosts": ["myapp.example.com"],
            "services": {
                "web": {
                    "port": 8080,
                    "routes": [{"path": "/"}],
                    "limits": {"memory": "256m"},
                },
            },
        }

    def test_no_staging_section_is_valid(self) -> None:
        manifest = self._base_manifest()
        errors, warnings = validate_manifest(manifest, "myapp")
        assert not errors

    def test_staging_copy_data_bool_is_valid(self) -> None:
        manifest = self._base_manifest()
        manifest["staging"] = {"copy_data": True}
        errors, warnings = validate_manifest(manifest, "myapp")
        assert not errors

    def test_staging_copy_data_non_bool_is_error(self) -> None:
        manifest = self._base_manifest()
        manifest["staging"] = {"copy_data": "yes"}
        errors, warnings = validate_manifest(manifest, "myapp")
        assert any("copy_data" in e and "boolean" in e for e in errors)

    def test_staging_unknown_keys_warned(self) -> None:
        manifest = self._base_manifest()
        manifest["staging"] = {"copy_data": True, "unknown_key": 42}
        errors, warnings = validate_manifest(manifest, "myapp")
        assert any("unknown_key" in w for w in warnings)


class TestSecurityValidation:
    def _base_manifest(self, **extra) -> dict:
        m = {
            "schema_version": 2,
            "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "source": "bundle",
            "project": "demo",
            "hosts": ["demo.example.com"],
            "services": {
                "web": {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"},
            },
        }
        m.update(extra)
        return m

    def test_current_schema_is_2(self) -> None:
        assert CURRENT_SCHEMA_VERSION == 2

    def test_no_security_block_passes(self) -> None:
        errors, _ = validate_manifest(self._base_manifest(), expected_name="demo")
        # security is optional
        assert all("security" not in e for e in errors)

    def test_off_without_reason_errors(self) -> None:
        m = self._base_manifest(security={"profile": "off"})
        errors, _ = validate_manifest(m, expected_name="demo")
        assert any("reason" in e for e in errors)

    def test_unknown_profile_errors(self) -> None:
        m = self._base_manifest(security={"profile": "ultra"})
        errors, _ = validate_manifest(m, expected_name="demo")
        assert any("profile" in e.lower() for e in errors)

    def test_service_security_validates_too(self) -> None:
        m = self._base_manifest()
        m["services"]["web"]["security"] = {"profile": "off"}  # missing reason
        errors, _ = validate_manifest(m, expected_name="demo")
        assert any("service:web" in e and "reason" in e for e in errors)

    def test_security_block_with_schema_v1_errors(self) -> None:
        """F3: declaring a security: block on a v1 manifest is an error.

        Catches the local-dev mistake of copying the new template into an
        un-migrated manifest. Real migrations bump schema_version
        automatically; an explicit v1 manifest with a security block is
        a configuration confusion we want to surface immediately.
        """
        m = self._base_manifest()
        m["schema_version"] = 1
        m["security"] = {"profile": "default"}
        errors, _ = validate_manifest(m, expected_name="demo")
        assert any(
            "security" in e and "schema_version" in e for e in errors
        ), f"expected schema_version coherence error, got: {errors}"

    def test_v1_without_security_block_passes(self) -> None:
        """A v1 manifest without a security block is still valid (legacy)."""
        m = self._base_manifest()
        m["schema_version"] = 1
        errors, _ = validate_manifest(m, expected_name="demo")
        # No security-related errors
        assert not any("security" in e for e in errors)

    def test_per_service_security_block_with_schema_v1_errors(self) -> None:
        m = self._base_manifest()
        m["schema_version"] = 1
        m["services"]["web"]["security"] = {"profile": "default"}
        errors, _ = validate_manifest(m, expected_name="demo")
        assert any(
            "security" in e and "schema_version" in e for e in errors
        )
