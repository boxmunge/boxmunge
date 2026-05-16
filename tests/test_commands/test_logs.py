"""Tests for boxmunge.commands.logs — `boxmunge logs` writable-hint postscript."""
from __future__ import annotations

import io
from contextlib import redirect_stderr

from boxmunge.commands.logs import _append_writable_postscript


class TestWritablePostscript:
    """Non-follow `boxmunge logs` appends a hint when read-only-fs
    errors appear in the captured output. Stays silent on clean output."""

    def test_clean_output_emits_nothing(self) -> None:
        clean = "INFO starting up\nINFO listening on :8000\n"
        buf = io.StringIO()
        with redirect_stderr(buf):
            _append_writable_postscript(clean)
        assert buf.getvalue() == ""

    def test_read_only_error_emits_postscript(self) -> None:
        logs = (
            'nginx: [emerg] mkdir() "/var/cache/nginx/temp" failed '
            '(30: Read-only file system)\n'
        )
        buf = io.StringIO()
        with redirect_stderr(buf):
            _append_writable_postscript(logs)
        out = buf.getvalue()
        assert "[HINT]" in out
        assert "/var/cache/nginx" in out
        assert "writable.ephemeral" in out

    def test_python_permission_error_emits_postscript(self) -> None:
        logs = "PermissionError: [Errno 30] Read-only file system: '/app/db.sqlite'\n"
        buf = io.StringIO()
        with redirect_stderr(buf):
            _append_writable_postscript(logs)
        out = buf.getvalue()
        assert "[HINT]" in out
        assert "/app/db.sqlite" in out

    def test_postscript_to_stderr_not_stdout(self) -> None:
        """The postscript must go to stderr — the captured docker output
        is on stdout and we want operators to be able to pipe stdout
        without picking up the hint."""
        import sys
        logs = (
            'nginx: [emerg] mkdir() "/var/cache/nginx/x" failed '
            '(30: Read-only file system)\n'
        )
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        original_stderr = sys.stderr
        sys.stderr = stderr_buf
        try:
            import contextlib
            with contextlib.redirect_stdout(stdout_buf):
                _append_writable_postscript(logs)
        finally:
            sys.stderr = original_stderr
        assert "[HINT]" not in stdout_buf.getvalue()
        assert "[HINT]" in stderr_buf.getvalue()

    def test_multiple_paths_listed(self) -> None:
        logs = (
            'nginx: [emerg] mkdir() "/var/cache/nginx/temp" failed '
            '(30: Read-only file system)\n'
            'nginx: [emerg] open() "/var/run/nginx.pid" failed '
            '(30: Read-only file system)\n'
        )
        buf = io.StringIO()
        with redirect_stderr(buf):
            _append_writable_postscript(logs)
        out = buf.getvalue()
        assert "/var/cache/nginx" in out
        assert "/var/run" in out
