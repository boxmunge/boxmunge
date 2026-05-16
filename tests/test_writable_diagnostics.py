"""Tests for boxmunge.writable_diagnostics — log scanner + hint formatter."""
from pathlib import Path

import pytest

from boxmunge.writable import WritableState
from boxmunge.writable_diagnostics import (
    WritableError,
    enrich_failure_with_writable_hint,
    format_hint,
    run_post_deploy_diagnostics,
    scan_line,
    scan_logs,
)


class TestScannerNginx:
    def test_nginx_emerg_mkdir_extracted(self) -> None:
        logs = (
            '2026/05/08 14:23:01 [emerg] mkdir() '
            '"/var/cache/nginx/client_temp" failed '
            '(30: Read-only file system)\n'
        )
        errors = scan_logs(logs)
        assert len(errors) == 1
        assert errors[0].path == "/var/cache/nginx"

    def test_nginx_emerg_open_pid_path_extracted(self) -> None:
        logs = (
            'nginx: [emerg] open() "/var/run/nginx.pid" failed '
            '(30: Read-only file system)\n'
        )
        errors = scan_logs(logs)
        assert len(errors) == 1
        assert errors[0].path == "/var/run"


class TestScannerGeneric:
    def test_python_permission_error_open(self) -> None:
        logs = (
            "PermissionError: [Errno 30] Read-only file system: "
            "'/app/cache.db'\n"
        )
        errors = scan_logs(logs)
        assert len(errors) == 1
        assert errors[0].path == "/app/cache.db"

    def test_mkdir_shell_form(self) -> None:
        logs = (
            "mkdir: cannot create directory '/var/lib/myapp': "
            "Read-only file system\n"
        )
        errors = scan_logs(logs)
        assert len(errors) == 1
        assert errors[0].path == "/var/lib/myapp"

    def test_erofs_with_path(self) -> None:
        logs = "EROFS: read-only file system, open '/etc/myapp.conf'\n"
        errors = scan_logs(logs)
        assert len(errors) == 1
        assert errors[0].path == "/etc/myapp.conf"


class TestScannerEdgeCases:
    def test_empty_logs(self) -> None:
        assert scan_logs("") == []

    def test_no_relevant_lines(self) -> None:
        logs = "INFO: server started on port 8000\nGET /health 200\n"
        assert scan_logs(logs) == []

    def test_words_in_text_dont_trigger(self) -> None:
        # Text mentioning "read-only" but not as an error
        logs = (
            "User reported 'read-only' file behaviour, investigating.\n"
            "Documentation mentions Read-only files as a feature.\n"
        )
        assert scan_logs(logs) == []

    def test_duplicate_paths_deduplicated(self) -> None:
        logs = (
            'nginx: [emerg] mkdir() "/var/cache/nginx/proxy_temp" failed '
            '(30: Read-only file system)\n'
            'nginx: [emerg] mkdir() "/var/cache/nginx/fastcgi_temp" failed '
            '(30: Read-only file system)\n'
        )
        errors = scan_logs(logs)
        # Both lines map to /var/cache/nginx — should dedupe
        assert len(errors) == 1
        assert errors[0].path == "/var/cache/nginx"

    def test_multiple_distinct_paths(self) -> None:
        logs = (
            'nginx: [emerg] open() "/var/run/nginx.pid" failed '
            '(30: Read-only file system)\n'
            'nginx: [emerg] mkdir() "/var/cache/nginx/temp" failed '
            '(30: Read-only file system)\n'
        )
        errors = scan_logs(logs)
        paths = {e.path for e in errors}
        assert "/var/run" in paths
        assert "/var/cache/nginx" in paths
        assert len(errors) == 2


class TestScanLine:
    def test_scan_line_returns_none_on_clean_line(self) -> None:
        assert scan_line("INFO server started\n") is None

    def test_scan_line_returns_error_on_match(self) -> None:
        line = (
            'nginx: [emerg] mkdir() "/var/cache/nginx/temp" failed '
            '(30: Read-only file system)'
        )
        err = scan_line(line)
        assert err is not None
        assert err.path == "/var/cache/nginx"


class TestHintFormatter:
    def test_hint_state_default_points_at_manifest(self) -> None:
        err = WritableError(path="/var/cache/nginx", raw="...")
        hint = format_hint([err], service="web", state=WritableState.DEFAULT)
        assert "services.web.writable.ephemeral" in hint
        assert "/var/cache/nginx" in hint

    def test_hint_state_managed_points_at_manifest(self) -> None:
        err = WritableError(path="/var/cache/nginx", raw="...")
        hint = format_hint([err], service="web", state=WritableState.MANAGED)
        assert "services.web.writable.ephemeral" in hint
        assert "/var/cache/nginx" in hint

    def test_hint_state_external_points_at_compose(self) -> None:
        err = WritableError(path="/var/cache/nginx", raw="...")
        hint = format_hint([err], service="web", state=WritableState.EXTERNAL)
        assert "compose.yml" in hint
        assert "externally-managed" in hint

    def test_hint_empty_returns_empty(self) -> None:
        assert format_hint([], "web", WritableState.DEFAULT) == ""

    def test_hint_multiple_paths_listed(self) -> None:
        errors = [
            WritableError(path="/var/cache/nginx", raw="..."),
            WritableError(path="/var/run", raw="..."),
        ]
        hint = format_hint(errors, "web", WritableState.DEFAULT)
        assert "/var/cache/nginx" in hint
        assert "/var/run" in hint

    def test_hint_includes_hint_marker(self) -> None:
        # Hint output is identifiable by an `[HINT]` prefix so log readers
        # can spot it.
        err = WritableError(path="/x", raw="...")
        hint = format_hint([err], "web", WritableState.DEFAULT)
        assert "[HINT]" in hint


# ---------------------------------------------------------------------------
# Post-deploy orchestration: sleep + per-service log scan + hint dict
# ---------------------------------------------------------------------------


class TestRunPostDeployDiagnostics:
    """Verify the orchestrator: dependency injection, service filtering,
    hint construction. The sleep_fn injection lets us run the suite at
    full speed without real wall-clock waits."""

    def _manifest(self, services: dict) -> dict:
        return {"project": "demo", "services": services}

    def test_no_services_returns_empty(self, tmp_path: Path) -> None:
        manifest = self._manifest({})
        result = run_post_deploy_diagnostics(
            tmp_path, manifest, sleep_fn=lambda _: None,
        )
        assert result == {}

    def test_logs_without_errors_returns_empty(self, tmp_path: Path) -> None:
        manifest = self._manifest({"web": {"port": 80, "routes": [{"path": "/"}]}})
        result = run_post_deploy_diagnostics(
            tmp_path, manifest,
            sleep_fn=lambda _: None,
            log_fetcher=lambda svc: "INFO: starting up\n",
        )
        assert result == {}

    def test_logs_with_read_only_error_returns_hint(self, tmp_path: Path) -> None:
        manifest = self._manifest({"web": {"port": 80, "routes": [{"path": "/"}]}})
        result = run_post_deploy_diagnostics(
            tmp_path, manifest,
            sleep_fn=lambda _: None,
            log_fetcher=lambda svc: (
                'nginx: [emerg] mkdir() "/var/cache/nginx/temp" failed '
                '(30: Read-only file system)\n'
            ),
        )
        assert "web" in result
        hint = result["web"]
        assert "[HINT]" in hint
        assert "/var/cache/nginx" in hint
        assert "services.web.writable.ephemeral" in hint

    def test_external_service_skipped(self, tmp_path: Path) -> None:
        manifest = self._manifest({
            "web": {
                "port": 80, "routes": [{"path": "/"}],
                "writable": {"external": True},
            },
        })
        # log_fetcher would never be called for skipped services. Make it
        # error to prove it's not invoked.
        def _no_fetch(svc):
            raise AssertionError(f"unexpected fetch for {svc!r}")

        result = run_post_deploy_diagnostics(
            tmp_path, manifest,
            sleep_fn=lambda _: None,
            log_fetcher=_no_fetch,
        )
        assert result == {}

    def test_managed_service_state_hint_points_at_manifest(
        self, tmp_path: Path,
    ) -> None:
        manifest = self._manifest({
            "web": {
                "port": 80, "routes": [{"path": "/"}],
                "writable": {"ephemeral": ["/some/other/path"]},
            },
        })
        result = run_post_deploy_diagnostics(
            tmp_path, manifest,
            sleep_fn=lambda _: None,
            log_fetcher=lambda svc: (
                'nginx: [emerg] mkdir() "/var/cache/nginx/temp" failed '
                '(30: Read-only file system)\n'
            ),
        )
        assert "web" in result
        # MANAGED still points at the manifest — operator extends the
        # writable.ephemeral list with the new path.
        assert "services.web.writable.ephemeral" in result["web"]

    def test_off_profile_service_skipped(self, tmp_path: Path) -> None:
        manifest = {
            "project": "demo",
            "services": {
                "web": {
                    "port": 80, "routes": [{"path": "/"}],
                    "security": {"profile": "off", "reason": "x"},
                },
            },
        }
        def _no_fetch(svc):
            raise AssertionError(f"unexpected fetch for {svc!r}")
        result = run_post_deploy_diagnostics(
            tmp_path, manifest,
            sleep_fn=lambda _: None,
            log_fetcher=_no_fetch,
        )
        assert result == {}

    def test_project_off_profile_skips_all_services(self, tmp_path: Path) -> None:
        manifest = {
            "project": "demo",
            "security": {"profile": "off", "reason": "x"},
            "services": {"web": {"port": 80, "routes": [{"path": "/"}]}},
        }
        def _no_fetch(svc):
            raise AssertionError(f"unexpected fetch for {svc!r}")
        result = run_post_deploy_diagnostics(
            tmp_path, manifest,
            sleep_fn=lambda _: None,
            log_fetcher=_no_fetch,
        )
        assert result == {}

    def test_log_fetcher_exception_is_silent(self, tmp_path: Path) -> None:
        manifest = self._manifest({"web": {"port": 80, "routes": [{"path": "/"}]}})

        def _boom(svc):
            raise RuntimeError("docker daemon unreachable")

        # Must not raise — diagnostics are non-fatal.
        result = run_post_deploy_diagnostics(
            tmp_path, manifest,
            sleep_fn=lambda _: None,
            log_fetcher=_boom,
        )
        assert result == {}

    def test_sleep_fn_called_with_sleep_seconds(self, tmp_path: Path) -> None:
        manifest = self._manifest({"web": {"port": 80, "routes": [{"path": "/"}]}})
        captured: list[float] = []
        run_post_deploy_diagnostics(
            tmp_path, manifest,
            sleep_seconds=8,
            sleep_fn=lambda s: captured.append(s),
            log_fetcher=lambda svc: "",
        )
        assert captured == [8]

    def test_sleep_skipped_when_no_targets(self, tmp_path: Path) -> None:
        # All services skipped → no point sleeping.
        manifest = self._manifest({
            "web": {
                "port": 80, "routes": [{"path": "/"}],
                "writable": {"external": True},
            },
        })
        captured: list[float] = []
        run_post_deploy_diagnostics(
            tmp_path, manifest,
            sleep_fn=lambda s: captured.append(s),
            log_fetcher=lambda svc: "",
        )
        assert captured == []

    def test_multiple_services_independent(self, tmp_path: Path) -> None:
        manifest = self._manifest({
            "web": {"port": 80, "routes": [{"path": "/"}]},
            "api": {"port": 8000, "routes": [{"path": "/api"}]},
        })
        def _fetch(svc):
            if svc == "web":
                return (
                    'nginx: [emerg] mkdir() "/var/cache/nginx/x" failed '
                    '(30: Read-only file system)\n'
                )
            return "INFO clean\n"
        result = run_post_deploy_diagnostics(
            tmp_path, manifest,
            sleep_fn=lambda _: None,
            log_fetcher=_fetch,
        )
        assert "web" in result
        assert "api" not in result


# ---------------------------------------------------------------------------
# enrich_failure_with_writable_hint — smoke-failure path
# ---------------------------------------------------------------------------


class TestEnrichFailureWithWritableHint:
    def _manifest(self, writable=None):
        svc = {"port": 80, "routes": [{"path": "/"}]}
        if writable is not None:
            svc["writable"] = writable
        return {"project": "demo", "services": {"web": svc}}

    def test_clean_logs_unchanged(self, tmp_path: Path) -> None:
        result = enrich_failure_with_writable_hint(
            "smoke timed out", tmp_path, self._manifest(), "web",
            log_fetcher=lambda svc: "INFO ok\n",
        )
        assert result == "smoke timed out"

    def test_read_only_error_appends_hint(self, tmp_path: Path) -> None:
        logs = (
            'nginx: [emerg] mkdir() "/var/cache/nginx/temp" failed '
            '(30: Read-only file system)\n'
        )
        result = enrich_failure_with_writable_hint(
            "Smoke test failed: connection refused",
            tmp_path, self._manifest(), "web",
            log_fetcher=lambda svc: logs,
        )
        assert "Smoke test failed: connection refused" in result
        assert "[HINT]" in result
        assert "/var/cache/nginx" in result
        assert "services.web.writable.ephemeral" in result

    def test_external_service_unchanged(self, tmp_path: Path) -> None:
        """Operator owns writability — hint would mislead."""
        logs = (
            'nginx: [emerg] mkdir() "/x" failed '
            '(30: Read-only file system)\n'
        )
        # log_fetcher should NEVER be called for external services.
        def _fetch(svc):
            raise AssertionError(f"unexpected fetch for {svc!r}")
        result = enrich_failure_with_writable_hint(
            "smoke failed", tmp_path,
            self._manifest(writable={"external": True}),
            "web",
            log_fetcher=_fetch,
        )
        assert result == "smoke failed"

    def test_managed_service_hint_points_at_manifest(
        self, tmp_path: Path,
    ) -> None:
        logs = (
            'nginx: [emerg] mkdir() "/new/path/temp" failed '
            '(30: Read-only file system)\n'
        )
        result = enrich_failure_with_writable_hint(
            "smoke failed", tmp_path,
            self._manifest(writable={"ephemeral": ["/some/other"]}),
            "web",
            log_fetcher=lambda svc: logs,
        )
        assert "[HINT]" in result
        assert "services.web.writable.ephemeral" in result

    def test_unknown_service_unchanged(self, tmp_path: Path) -> None:
        # Service not in manifest — should pass through silently.
        result = enrich_failure_with_writable_hint(
            "smoke failed", tmp_path,
            self._manifest(), "nonexistent",
            log_fetcher=lambda svc: "logs",
        )
        assert result == "smoke failed"

    def test_log_fetcher_exception_unchanged(self, tmp_path: Path) -> None:
        def _boom(svc):
            raise RuntimeError("daemon down")
        result = enrich_failure_with_writable_hint(
            "smoke failed", tmp_path,
            self._manifest(), "web",
            log_fetcher=_boom,
        )
        assert result == "smoke failed"

    def test_empty_logs_unchanged(self, tmp_path: Path) -> None:
        result = enrich_failure_with_writable_hint(
            "smoke failed", tmp_path,
            self._manifest(), "web",
            log_fetcher=lambda svc: "",
        )
        assert result == "smoke failed"
