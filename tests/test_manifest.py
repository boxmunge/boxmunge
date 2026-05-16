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

    def test_current_schema_is_3(self) -> None:
        assert CURRENT_SCHEMA_VERSION == 3

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


class TestHostnameValidation:
    """Audit Finding 12: hostnames flow into the Caddyfile via simple
    ``", ".join(hosts)`` and a host containing a newline or directive
    metacharacter could inject Caddy directives. Validate per-entry."""

    def _manifest(self, hosts: list[str], **extra: object) -> dict:
        m = {
            "id": "01TEST", "project": "demo", "source": "bundle",
            "hosts": hosts,
            "services": {"web": {"port": 3000, "routes": [{"path": "/"}]}},
        }
        m.update(extra)
        return m

    def test_plain_domain_accepted(self) -> None:
        errors, _ = validate_manifest(self._manifest(["example.com"]), "demo")
        assert not any("hosts" in e.lower() and "invalid" in e.lower() for e in errors)

    def test_subdomain_accepted(self) -> None:
        errors, _ = validate_manifest(self._manifest(["app.example.com"]), "demo")
        assert not any("invalid" in e.lower() for e in errors)

    def test_localhost_accepted(self) -> None:
        errors, _ = validate_manifest(self._manifest(["localhost"]), "demo")
        assert not any("invalid" in e.lower() for e in errors)

    def test_wildcard_rejected_without_optin(self) -> None:
        errors, _ = validate_manifest(self._manifest(["*.example.com"]), "demo")
        assert any(
            "wildcard" in e.lower() and "allow_wildcard_hosts" in e
            for e in errors
        )

    def test_wildcard_accepted_with_optin(self) -> None:
        m = self._manifest(["*.example.com"], allow_wildcard_hosts=True)
        errors, _ = validate_manifest(m, "demo")
        assert not any("wildcard" in e.lower() for e in errors)

    def test_embedded_newline_rejected(self) -> None:
        errors, _ = validate_manifest(
            self._manifest(["evil.com\nlocalhost {"]), "demo",
        )
        assert any("invalid" in e.lower() for e in errors)

    def test_directive_chars_rejected(self) -> None:
        errors, _ = validate_manifest(
            self._manifest(["; ls /etc; #"]), "demo",
        )
        assert any("invalid" in e.lower() for e in errors)

    def test_uppercase_rejected_with_friendly_message(self) -> None:
        errors, _ = validate_manifest(self._manifest(["EXAMPLE.COM"]), "demo")
        assert any(
            "invalid" in e.lower() and "lowercase" in e.lower() for e in errors
        )

    def test_port_in_host_rejected(self) -> None:
        errors, _ = validate_manifest(
            self._manifest(["example.com:8080"]), "demo",
        )
        assert any("invalid" in e.lower() for e in errors)

    def test_curly_braces_rejected(self) -> None:
        errors, _ = validate_manifest(
            self._manifest(["example.com {"]), "demo",
        )
        assert any("invalid" in e.lower() for e in errors)

    def test_backtick_rejected(self) -> None:
        errors, _ = validate_manifest(
            self._manifest(["`echo evil`.com"]), "demo",
        )
        assert any("invalid" in e.lower() for e in errors)


class TestManifestShapeGuards:
    """Audit Finding 11: isinstance guards on top-level + section types.

    Without these guards, malformed manifests AttributeError deep inside the
    validator instead of producing an actionable error message.
    """

    def test_top_level_string_rejected_clearly(self) -> None:
        # `yaml.safe_load("just a string")` returns "just a string", not dict.
        errors, _ = validate_manifest("just a string", expected_name="demo")
        assert any("mapping" in e.lower() and "manifest" in e.lower() for e in errors)

    def test_top_level_list_rejected_clearly(self) -> None:
        errors, _ = validate_manifest(["a", "b"], expected_name="demo")
        assert any("mapping" in e.lower() and "manifest" in e.lower() for e in errors)

    def test_top_level_none_rejected_clearly(self) -> None:
        # Empty manifest file -> safe_load returns None.
        errors, _ = validate_manifest(None, expected_name="demo")
        assert any("mapping" in e.lower() and "manifest" in e.lower() for e in errors)

    def test_services_as_list_rejected_clearly(self) -> None:
        manifest = {
            "id": "01TEST", "project": "demo", "source": "bundle",
            "hosts": ["demo.example.com"],
            "services": ["web", "worker"],
        }
        errors, _ = validate_manifest(manifest, expected_name="demo")
        assert any("services" in e and "mapping" in e for e in errors)
        # Must not have AttributeError'd on .items() somewhere along the way.

    def test_services_as_string_rejected_clearly(self) -> None:
        manifest = {
            "id": "01TEST", "project": "demo", "source": "bundle",
            "hosts": ["demo.example.com"],
            "services": "web",
        }
        errors, _ = validate_manifest(manifest, expected_name="demo")
        assert any("services" in e and "mapping" in e for e in errors)

    def test_security_as_list_rejected_clearly(self) -> None:
        manifest = {
            "schema_version": 2,
            "id": "01TEST", "project": "demo", "source": "bundle",
            "hosts": ["demo.example.com"],
            "services": {"web": {"port": 3000, "routes": [{"path": "/"}]}},
            "security": ["profile", "default"],
        }
        errors, _ = validate_manifest(manifest, expected_name="demo")
        assert any("security" in e and "mapping" in e for e in errors)

    def test_backup_as_list_rejected_clearly(self) -> None:
        manifest = {
            "id": "01TEST", "project": "demo", "source": "bundle",
            "hosts": ["demo.example.com"],
            "services": {"web": {"port": 3000, "routes": [{"path": "/"}]}},
            "backup": ["type", "none"],
        }
        errors, _ = validate_manifest(manifest, expected_name="demo")
        assert any("backup" in e and "mapping" in e for e in errors)

    def test_staging_as_list_rejected_clearly(self) -> None:
        manifest = {
            "id": "01TEST", "project": "demo", "source": "bundle",
            "hosts": ["demo.example.com"],
            "services": {"web": {"port": 3000, "routes": [{"path": "/"}]}},
            "staging": ["copy_data", True],
        }
        errors, _ = validate_manifest(manifest, expected_name="demo")
        assert any("staging" in e and "mapping" in e for e in errors)


class TestWritableManifestIntegration:
    """v0.9: writable: block validation through validate_manifest."""

    def _base(self, **extra) -> dict:
        m = {
            "schema_version": 3,
            "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "source": "bundle",
            "project": "demo",
            "hosts": ["demo.example.com"],
            "services": {
                "web": {
                    "port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh",
                },
            },
        }
        m.update(extra)
        return m

    def test_schema_v3_no_writable_block_passes(self) -> None:
        errors, _ = validate_manifest(self._base(), expected_name="demo")
        assert all("writable" not in e for e in errors)

    def test_schema_v2_no_writable_block_still_loads(self) -> None:
        m = self._base()
        m["schema_version"] = 2
        errors, _ = validate_manifest(m, expected_name="demo")
        assert all("writable" not in e for e in errors)

    def test_writable_block_on_schema_v2_errors(self) -> None:
        m = self._base()
        m["schema_version"] = 2
        m["services"]["web"]["writable"] = {"ephemeral": ["/var/cache"]}
        errors, _ = validate_manifest(m, expected_name="demo")
        assert any(
            "writable" in e and "schema_version" in e for e in errors
        ), f"expected schema_version coherence error, got: {errors}"

    def test_writable_block_on_schema_v1_errors(self) -> None:
        m = self._base()
        m["schema_version"] = 1
        m["services"]["web"]["writable"] = {"ephemeral": ["/var/cache"]}
        errors, _ = validate_manifest(m, expected_name="demo")
        assert any(
            "writable" in e and "schema_version" in e for e in errors
        )

    def test_writable_validation_errors_propagate(self) -> None:
        m = self._base()
        m["services"]["web"]["writable"] = {"ephemeral": ["relative/path"]}
        errors, _ = validate_manifest(m, expected_name="demo")
        assert any("absolute" in e for e in errors)

    def test_writable_external_validation_propagates(self) -> None:
        m = self._base()
        m["services"]["web"]["writable"] = {
            "external": True, "ephemeral": ["/x"],
        }
        errors, _ = validate_manifest(m, expected_name="demo")
        assert any("mutually exclusive" in e for e in errors)

    def test_writable_persistent_valid_accepts(self) -> None:
        m = self._base()
        m["services"]["web"]["writable"] = {
            "persistent": [{"name": "data", "mount": "/app/data"}],
        }
        errors, _ = validate_manifest(m, expected_name="demo")
        assert all("writable" not in e for e in errors)

    def test_writable_error_includes_service_name(self) -> None:
        m = self._base()
        m["services"]["web"]["writable"] = {"ephemeral": ["bad"]}
        errors, _ = validate_manifest(m, expected_name="demo")
        assert any("services.web" in e for e in errors), errors

    def test_per_service_writable_independent(self) -> None:
        """Multiple services with different writable states all validate."""
        m = self._base()
        m["services"]["web"]["writable"] = {"ephemeral": ["/var/cache"]}
        m["services"]["api"] = {
            "port": 8000, "routes": [{"path": "/api"}], "smoke": "y.sh",
            "writable": {"external": True},
        }
        m["services"]["worker"] = {
            "port": 9000, "routes": [{"path": "/w"}], "internal": True,
            "smoke": "z.sh",
            # no writable block — DEFAULT
        }
        errors, _ = validate_manifest(m, expected_name="demo")
        assert all("writable" not in e for e in errors), errors

    def test_malformed_writable_block_errors_cleanly(self) -> None:
        m = self._base()
        m["services"]["web"]["writable"] = "not a mapping"
        errors, _ = validate_manifest(m, expected_name="demo")
        assert any("writable" in e and "mapping" in e for e in errors)
