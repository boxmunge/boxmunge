"""Tests for boxmunge.commands.logs — `boxmunge logs` writable-hint postscript."""
from __future__ import annotations

import io
from contextlib import redirect_stderr
from unittest.mock import patch

import pytest

from boxmunge.commands.logs import _append_writable_postscript, cmd_logs
from boxmunge.staged_release import STAGING_BASE, STAGING_OVERLAY, slot_dir


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


# ---- which compose project `logs` reads: production, or staging (--staging)


@pytest.fixture
def box(paths):
    pdir = paths.project_dir("myapp")
    pdir.mkdir(parents=True)
    (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    (pdir / "compose.boxmunge.yml").write_text("services: {}\n")
    with patch("boxmunge.commands.logs.BoxPaths", return_value=paths):
        yield paths


def _run(args, capture="out\n"):
    with patch("boxmunge.commands.logs.compose_logs_capture",
               return_value=capture) as cap, \
            patch("boxmunge.commands.logs.compose_logs") as follow, \
            pytest.raises(SystemExit) as done:
        cmd_logs(args)
        raise SystemExit(0)
    return done.value.code, cap, follow


def test_production_logs_read_the_project(box) -> None:
    rc, cap, _ = _run(["myapp", "web"])
    assert rc == 0
    kw = cap.call_args.kwargs
    assert kw["project_name"] == "myapp" and kw["service"] == "web"
    assert kw["compose_files"] == ["compose.yml", "compose.boxmunge.yml"]


def test_staging_logs_read_the_slot(box) -> None:
    slot = slot_dir(box, "myapp")
    (slot / "release").mkdir(parents=True)
    rc, cap, _ = _run(["myapp", "--staging", "--tail", "20"])
    assert rc == 0
    kw = cap.call_args.kwargs
    assert kw["project_name"] == "myapp-staging"
    assert kw["compose_files"] == [str(slot / STAGING_BASE), str(slot / STAGING_OVERLAY)]
    assert kw["project_directory"] == slot / "release"
    assert kw["tail"] == 20
    assert cap.call_args.args[0] == slot / "release"


def test_staging_follow_streams_the_slot(box) -> None:
    (slot_dir(box, "myapp") / "release").mkdir(parents=True)
    rc, _, follow = _run(["myapp", "web", "--staging", "--follow"])
    assert rc == 0
    kw = follow.call_args.kwargs
    assert kw["project_name"] == "myapp-staging" and kw["follow"] is True
    assert kw["service"] == "web"


def test_staging_logs_of_a_0_10_1_stage_read_the_project_dir(box) -> None:
    pdir = box.project_dir("myapp")
    (pdir / "compose.boxmunge-staging.yml").write_text("services: {}\n")
    rc, cap, _ = _run(["myapp", "--staging"])
    assert rc == 0
    kw = cap.call_args.kwargs
    assert kw["project_name"] == "myapp-staging"
    assert kw["compose_files"] == ["compose.yml", "compose.boxmunge-staging.yml"]
    assert cap.call_args.args[0] == pdir


def test_staging_logs_with_nothing_staged_name_the_way_on(box, capsys) -> None:
    rc, cap, _ = _run(["myapp", "--staging"])
    assert rc == 1
    cap.assert_not_called()
    err = capsys.readouterr().err
    assert "stage myapp" in err and "logs myapp" in err


def test_staging_name_points_at_the_flag(box, capsys) -> None:
    rc, cap, _ = _run(["myapp-staging"])
    assert rc == 2
    cap.assert_not_called()
    assert "logs myapp --staging" in capsys.readouterr().err


def test_planted_slot_is_refused(box, capsys, tmp_path) -> None:
    slot = slot_dir(box, "myapp")
    slot.parent.mkdir(parents=True)
    slot.symlink_to(tmp_path)
    rc, cap, _ = _run(["myapp", "--staging"])
    assert rc == 1
    cap.assert_not_called()
    assert "symbolic link" in capsys.readouterr().err


def test_legacy_project_dir_of_that_name_gets_the_rename_hint(box, capsys) -> None:
    (box.projects / "myapp-staging").mkdir()
    rc, cap, _ = _run(["myapp-staging"])
    assert rc == 2
    cap.assert_not_called()
    err = capsys.readouterr().err
    assert "Choose a name without the suffix" in err
    assert "logs myapp --staging" not in err
