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
    check_lifecycle_blocked,
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

    def test_skip_is_exit_code_neutral(self) -> None:
        """A 'skip' (couldn't-check, e.g. needs root) must not affect the
        exit code — health stays HEALTHY when everything else is ok."""
        report = HealthReport(checks=[
            HealthCheck("docker", "ok", "Running"),
            HealthCheck("ufw", "skip", "requires root"),
        ])
        assert report.exit_code == 0
        text = report.format_text()
        assert "SKIP" in text
        assert "HEALTHY" in text

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


class TestCheckConfigDriftSkipsBlocked:
    """When a project is paused/quarantined its .conf intentionally holds
    the maintenance fragment. Comparing that against generate_caddy_config
    would warn 'drift' on an intentional state — false positive."""

    def test_quarantined_project_does_not_warn_as_drift(
        self, tmp_path: Path,
    ) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects/myapp", "caddy/sites", "state/deploy"]:
            (paths.root / d).mkdir(parents=True)
        paths.project_manifest("myapp").write_text(yaml.dump({
            "schema_version": 1, "id": "01TEST", "project": "myapp",
            "source": "bundle", "hosts": ["myapp.test"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }))
        # Maintenance fragment, not generated proxy block.
        paths.project_caddy_site("myapp").write_text(
            "myapp.test {\n  handle {\n    root * /etc/caddy/maintenance\n  }\n}\n"
        )
        paths.project_quarantine_state("myapp").write_text("{}")
        check = check_config_drift(paths)
        assert check.status == "ok"
        assert "myapp" not in check.detail


class TestCheckLifecycleBlocked:
    def _make_project(self, paths: BoxPaths, name: str) -> None:
        for d in [f"projects/{name}", "state/deploy"]:
            (paths.root / d).mkdir(parents=True, exist_ok=True)
        paths.project_manifest(name).write_text(yaml.dump({
            "schema_version": 1, "id": "01TEST", "project": name,
            "source": "bundle", "hosts": [f"{name}.test"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }))

    def test_no_blocked_projects_is_ok(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.projects.mkdir(parents=True)
        self._make_project(paths, "alpha")
        check = check_lifecycle_blocked(paths)
        assert check.status == "ok"
        assert "No projects in blocked states" in check.detail

    def test_paused_only_is_ok_with_note(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.projects.mkdir(parents=True)
        self._make_project(paths, "alpha")
        paths.project_paused_state("alpha").write_text(
            '{"paused_at": "2026-05-30T00:00:00+00:00"}',
        )
        check = check_lifecycle_blocked(paths)
        assert check.status == "ok"
        assert "paused: alpha" in check.detail

    def test_quarantined_warns_with_cve(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.projects.mkdir(parents=True)
        self._make_project(paths, "alpha")
        paths.project_quarantine_state("alpha").write_text(json.dumps({
            "quarantined_at": "2026-05-28T03:11:49+00:00",
            "cve_id": "CVE-2026-42496",
            "severity": "Critical",
            "effective_severity": "Critical",
            "explanation": "Critical, no upstream fix",
        }))
        check = check_lifecycle_blocked(paths)
        assert check.status == "warn"
        assert "alpha" in check.detail
        assert "CVE-2026-42496" in check.detail

    def test_quarantine_takes_precedence_over_paused(
        self, tmp_path: Path,
    ) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.projects.mkdir(parents=True)
        self._make_project(paths, "alpha")
        paths.project_paused_state("alpha").write_text(
            '{"paused_at": "2026-05-30T00:00:00+00:00"}',
        )
        paths.project_quarantine_state("alpha").write_text(json.dumps({
            "quarantined_at": "2026-05-28T03:11:49+00:00",
            "cve_id": "CVE-2026-42496",
            "effective_severity": "Critical",
        }))
        check = check_lifecycle_blocked(paths)
        assert check.status == "warn"
        # Mirrors lifecycle.is_blocked ordering: a project counted twice
        # would be a bug.
        assert "alpha" in check.detail
        assert check.detail.count("alpha") == 1
        # Listed under quarantined, not paused.
        assert "paused:" not in check.detail


class TestCheckProjectContainersSkipsQuarantined:
    """Wave 1: check_project_containers must NOT mis-attribute a deliberately-
    stopped (CVE-quarantined) project as a health failure. Mirrors the
    paused-skip behavior."""

    def _make_project(self, paths: BoxPaths, name: str) -> None:
        for d in ["projects/" + name, "caddy/sites"]:
            (paths.root / d).mkdir(parents=True, exist_ok=True)
        manifest = {
            "schema_version": 1,
            "id": "01TEST",
            "project": name,
            "source": "bundle",
            "hosts": [f"{name}.test"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        paths.project_manifest(name).write_text(yaml.dump(manifest))

    def test_quarantined_project_not_reported_as_down(
        self, tmp_path: Path,
    ) -> None:
        from unittest.mock import patch
        from boxmunge.commands.health_cmd import check_project_containers
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config"]:
            (paths.root / d).mkdir(parents=True, exist_ok=True)
        self._make_project(paths, "alpha")
        # Mark alpha CVE-quarantined.
        paths.project_quarantine_state("alpha").parent.mkdir(
            parents=True, exist_ok=True,
        )
        paths.project_quarantine_state("alpha").write_text("{}")

        # If subprocess.run gets called, it means we did NOT skip the
        # quarantined project. Make it explode if invoked.
        with patch(
            "boxmunge.commands.health_cmd.subprocess.run",
            side_effect=AssertionError(
                "subprocess.run must not be called for a quarantined project",
            ),
        ):
            check = check_project_containers(paths)
        # alpha was the only project and it was quarantined → no project
        # checked → "All N project(s) have running containers" reads 0.
        assert check.status == "ok"


class TestSshPortLookup:
    """run_health logs and falls back to 922 when load_config raises
    ConfigError, instead of swallowing every exception in sight."""

    def test_config_error_logged_and_default_used(self, paths: BoxPaths) -> None:
        from unittest.mock import patch
        from boxmunge.commands.health_cmd import run_health
        from boxmunge.config import ConfigError

        ok_check = HealthCheck("stub", "ok", "")
        captured_ssh_port: dict[str, int] = {}

        def capture_ufw(ssh_port: int = 922) -> HealthCheck:
            captured_ssh_port["value"] = ssh_port
            return ok_check

        # Patch every check so we can run end-to-end without touching the
        # host. The ssh_port path uses local imports, so we patch at the
        # source modules.
        from contextlib import ExitStack
        with ExitStack() as stack:
            for t in [
                "boxmunge.commands.health_cmd.check_docker_running",
                "boxmunge.commands.health_cmd.check_caddy_container",
                "boxmunge.commands.health_cmd.check_system_container",
                "boxmunge.commands.health_cmd.check_file_permissions",
                "boxmunge.commands.health_cmd.check_age_key",
                "boxmunge.commands.health_cmd.check_project_containers",
                "boxmunge.commands.health_cmd.check_config_drift",
                "boxmunge.commands.health_cmd.check_recent_errors",
            ]:
                stack.enter_context(patch(t, return_value=ok_check))
            for t in [
                "boxmunge.health_checks.container_updates.check_container_updates",
                "boxmunge.health_checks.security.check_security_profiles",
                "boxmunge.health_checks.hardening.check_crowdsec",
                "boxmunge.health_checks.hardening.check_aide_status",
                "boxmunge.health_checks.hardening.check_auditd",
                "boxmunge.health_checks.hardening.check_unattended_upgrades",
                "boxmunge.health_checks.hardening.check_sysctl_hardening",
                "boxmunge.health_checks.hardening.check_systemd_timers",
            ]:
                stack.enter_context(patch(t, return_value=ok_check))
            stack.enter_context(patch(
                "boxmunge.health_checks.hardening.check_ufw",
                side_effect=capture_ufw,
            ))
            stack.enter_context(patch(
                "boxmunge.config.load_config",
                side_effect=ConfigError("file gone"),
            ))
            mw = stack.enter_context(patch("boxmunge.log.log_warning"))
            run_health(paths, as_json=True)

        assert captured_ssh_port["value"] == 922
        assert any(
            "ssh_port=922" in c.args[1] for c in mw.call_args_list
        ), (
            f"expected log_warning about ssh_port default; got {mw.call_args_list}"
        )
