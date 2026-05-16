"""Tests for boxmunge.writable_diagnostics — log scanner + hint formatter."""
import pytest

from boxmunge.writable import WritableState
from boxmunge.writable_diagnostics import (
    WritableError,
    format_hint,
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
