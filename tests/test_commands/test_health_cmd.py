"""Tests for boxmunge health command (unit tests)."""

import json
from pathlib import Path

import pytest
import yaml

from boxmunge.commands.health_cmd import (
    HealthCheck,
    HealthReport,
    check_age_key,
    check_config_drift,
    check_file_permissions,
)
from boxmunge.paths import BoxPaths


class TestHealthReport:
    def test_all_ok(self) -> None:
        report = HealthReport(checks=[
            HealthCheck("docker", "ok", "Running"),
            HealthCheck("caddy", "ok", "Healthy"),
        ])
        assert report.exit_code == 0

    def test_warning_returns_1(self) -> None:
        report = HealthReport(checks=[
            HealthCheck("docker", "ok", ""),
            HealthCheck("timers", "warn", "backup timer inactive"),
        ])
        assert report.exit_code == 1

    def test_error_returns_2(self) -> None:
        report = HealthReport(checks=[
            HealthCheck("docker", "ok", ""),
            HealthCheck("caddy", "error", "Not running"),
        ])
        assert report.exit_code == 2

    def test_json_output(self) -> None:
        report = HealthReport(checks=[
            HealthCheck("docker", "ok", "Running"),
        ])
        data = json.loads(report.format_json())
        assert data["checks"][0]["name"] == "docker"
        assert data["checks"][0]["status"] == "ok"

    def test_text_output(self) -> None:
        report = HealthReport(checks=[
            HealthCheck("docker", "ok", "Running"),
            HealthCheck("caddy", "error", "Not running"),
        ])
        text = report.format_text()
        assert "OK" in text
        assert "ERR" in text
        assert "ISSUES FOUND" in text


class TestCheckFilePermissions:
    def test_correct_permissions(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.config.mkdir(parents=True)
        paths.backup_key.write_text("key")
        paths.backup_key.chmod(0o600)
        check = check_file_permissions(paths)
        assert check.status == "ok"

    def test_wrong_permissions(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.config.mkdir(parents=True)
        paths.backup_key.write_text("key")
        paths.backup_key.chmod(0o644)
        check = check_file_permissions(paths)
        assert check.status == "warn"


class TestCheckAgeKey:
    def test_valid_key(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.config.mkdir(parents=True)
        paths.backup_key.write_text(
            "# public key: age1xxx\nAGE-SECRET-KEY-1XXX\n"
        )
        check = check_age_key(paths)
        assert check.status == "ok"

    def test_missing_key(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        check = check_age_key(paths)
        assert check.status == "error"

    def test_invalid_key(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.config.mkdir(parents=True)
        paths.backup_key.write_text("not an age key\n")
        check = check_age_key(paths)
        assert check.status == "error"


class TestCheckConfigDrift:
    def test_detects_drift(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects/myapp", "caddy/sites"]:
            (paths.root / d).mkdir(parents=True)
        manifest = {
            "schema_version": 1,
            "id": "01TEST",
            "project": "myapp",
            "source": "bundle",
            "hosts": ["myapp.test"],
            "services": {
                "web": {"port": 8080, "routes": [{"path": "/"}]},
            },
        }
        paths.project_manifest("myapp").write_text(yaml.dump(manifest))
        paths.project_caddy_site("myapp").write_text("wrong config here")
        check = check_config_drift(paths)
        assert check.status == "warn"
        assert "myapp" in check.detail

    def test_no_drift(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects/myapp", "caddy/sites"]:
            (paths.root / d).mkdir(parents=True)
        manifest = {
            "schema_version": 1,
            "id": "01TEST",
            "project": "myapp",
            "source": "bundle",
            "hosts": ["myapp.test"],
            "services": {
                "web": {"port": 8080, "routes": [{"path": "/"}]},
            },
        }
        paths.project_manifest("myapp").write_text(yaml.dump(manifest))
        from boxmunge.caddy import generate_caddy_config
        paths.project_caddy_site("myapp").write_text(
            generate_caddy_config(manifest)
        )
        check = check_config_drift(paths)
        assert check.status == "ok"
