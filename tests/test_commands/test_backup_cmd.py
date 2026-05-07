"""Tests for boxmunge backup command logic."""

import fcntl
import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

import boxmunge.commands.backup_cmd as backup_cmd
from boxmunge.commands.backup_cmd import run_backup, run_backup_all, list_snapshots
from boxmunge.pause import write_paused_state
from boxmunge.paths import BoxPaths


MANIFEST_WITH_BACKUP = """\
project: myapp
repo: ""
ref: main
hosts:
  - myapp.example.com
services:
  web:
    type: frontend
    port: 3000
    routes:
      - path: /
backup:
  type: db-dump
  dump_command: "boxmunge-scripts/backup.sh"
  restore_command: "boxmunge-scripts/restore.sh"
  retention: 3
env_files: []
"""

MANIFEST_NO_BACKUP = """\
project: myapp
repo: ""
ref: main
hosts:
  - myapp.example.com
services:
  web:
    type: frontend
    port: 3000
    routes:
      - path: /
backup:
  type: none
env_files: []
"""


def _setup_project(paths: BoxPaths, manifest: str) -> None:
    pdir = paths.project_dir("myapp")
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(manifest)
    (pdir / "backups").mkdir()
    scripts = pdir / "boxmunge-scripts"
    scripts.mkdir()
    (scripts / "backup.sh").write_text("#!/bin/bash\necho 'dump data'")
    (scripts / "backup.sh").chmod(0o755)
    paths.backup_key.parent.mkdir(parents=True, exist_ok=True)
    paths.backup_key.write_text("dGVzdC1rZXktZm9yLWJhY2t1cHM=\n")


class TestRunBackup:
    @patch("boxmunge.commands.backup_cmd._execute_dump")
    @patch("boxmunge.backup.encrypt_file")
    def test_backup_succeeds_with_dump_type(
        self, mock_encrypt: MagicMock, mock_dump: MagicMock, paths: BoxPaths
    ) -> None:
        _setup_project(paths, MANIFEST_WITH_BACKUP)
        mock_dump.return_value = paths.project_dir("myapp") / "backups" / "raw.tar.gz"
        mock_dump.return_value.write_bytes(b"fake")

        exit_code = run_backup("myapp", paths)
        assert exit_code == 0
        mock_dump.assert_called_once()
        mock_encrypt.assert_called_once()

    def test_backup_skipped_for_none_type(self, paths: BoxPaths) -> None:
        _setup_project(paths, MANIFEST_NO_BACKUP)
        exit_code = run_backup("myapp", paths)
        assert exit_code == 0

    def test_backup_fails_missing_project(self, paths: BoxPaths) -> None:
        exit_code = run_backup("nope", paths)
        assert exit_code == 1

    def test_backup_fails_pre_registered(self, paths: BoxPaths, capsys) -> None:
        pdir = paths.project_dir("myapp")
        pdir.mkdir(parents=True)
        (pdir / "secrets.env").write_text("KEY=val\n")

        exit_code = run_backup("myapp", paths)
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "pre-registered" in captured.err
        assert "boxmunge deploy myapp" in captured.err


class TestBackupRefusesPaused:
    def test_run_backup_refuses_paused(self, paths: BoxPaths, capsys) -> None:
        _setup_project(paths, MANIFEST_WITH_BACKUP)
        write_paused_state("myapp", paths)

        rc = run_backup("myapp", paths)
        assert rc == 1
        err = capsys.readouterr().err
        assert "paused" in err.lower()


class TestBackupAllSkipsPaused:
    @patch("boxmunge.commands.backup_cmd.run_backup")
    def test_skips_paused_in_all(
        self, mock_backup: MagicMock, paths: BoxPaths, capsys
    ) -> None:
        for name in ("myapp", "otherapp"):
            pdir = paths.project_dir(name)
            pdir.mkdir(parents=True)
            (pdir / "manifest.yml").write_text(
                MANIFEST_WITH_BACKUP.replace("project: myapp", f"project: {name}")
            )

        write_paused_state("myapp", paths)
        mock_backup.return_value = 0

        run_backup_all(paths)

        called_projects = [call.args[0] for call in mock_backup.call_args_list]
        assert "myapp" not in called_projects
        assert "otherapp" in called_projects

        captured = capsys.readouterr()
        assert "myapp" in captured.out
        assert "paused" in captured.out.lower()


class TestBackupSkipsQuarantined:
    """Wave 1: backups of stopped (CVE-quarantined) services are pointless
    and may surface confusing volume-empty warnings — skip cleanly."""

    @patch("boxmunge.commands.backup_cmd._execute_dump")
    @patch("boxmunge.backup.encrypt_file")
    def test_run_backup_skips_quarantined(
        self, mock_encrypt, mock_dump, paths: BoxPaths, capsys,
    ) -> None:
        _setup_project(paths, MANIFEST_WITH_BACKUP)
        paths.project_quarantine_state("myapp").parent.mkdir(
            parents=True, exist_ok=True,
        )
        paths.project_quarantine_state("myapp").write_text("{}")
        rc = run_backup("myapp", paths)
        # Skip is non-fatal — returns 0.
        assert rc == 0
        out = capsys.readouterr().out
        assert "quarantine" in out.lower()
        # Mutating helpers MUST NOT have run.
        mock_dump.assert_not_called()
        mock_encrypt.assert_not_called()

    @patch("boxmunge.commands.backup_cmd.run_backup")
    def test_skips_quarantined_in_all(
        self, mock_backup: MagicMock, paths: BoxPaths, capsys,
    ) -> None:
        for name in ("myapp", "otherapp"):
            pdir = paths.project_dir(name)
            pdir.mkdir(parents=True)
            (pdir / "manifest.yml").write_text(
                MANIFEST_WITH_BACKUP.replace("project: myapp", f"project: {name}")
            )
        # Quarantine myapp; otherapp stays normal.
        paths.project_quarantine_state("myapp").parent.mkdir(
            parents=True, exist_ok=True,
        )
        paths.project_quarantine_state("myapp").write_text("{}")
        mock_backup.return_value = 0

        run_backup_all(paths)

        called_projects = [call.args[0] for call in mock_backup.call_args_list]
        assert "myapp" not in called_projects
        assert "otherapp" in called_projects

        captured = capsys.readouterr()
        assert "myapp" in captured.out
        assert "quarantine" in captured.out.lower()


class TestBackupAllLockSkip:
    """4c: backup-all retries lock-held projects + Pushover-alerts persistent skips."""

    def _setup_two_projects(self, paths: BoxPaths) -> None:
        for name in ("alpha", "beta"):
            pdir = paths.project_dir(name)
            pdir.mkdir(parents=True)
            (pdir / "manifest.yml").write_text(
                MANIFEST_WITH_BACKUP.replace("project: myapp", f"project: {name}")
            )

    def _hold_project_lock(self, paths: BoxPaths, name: str) -> int:
        """Open and EX-lock the project's lock file. Returns the fd."""
        lock_path = paths.project_lock_file(name)
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    @patch("boxmunge.commands.backup_cmd._notify_persistent_locks")
    @patch("boxmunge.commands.backup_cmd.run_backup")
    def test_locked_project_is_retried_then_alerted(
        self, mock_backup: MagicMock, mock_notify: MagicMock,
        paths: BoxPaths, monkeypatch,
    ) -> None:
        """A project whose lock stays held past the retry budget must be
        reported via Pushover (not just silently rolled into rc=1)."""
        self._setup_two_projects(paths)
        # Shrink budget so the test runs in <1s.
        monkeypatch.setattr(backup_cmd, "_LOCK_RETRY_BUDGET_SECONDS", 0.2)
        monkeypatch.setattr(backup_cmd, "_LOCK_RETRY_INTERVAL_SECONDS", 0.05)

        # alpha's lock is held for the entirety of the test.
        fd = self._hold_project_lock(paths, "alpha")
        try:
            mock_backup.return_value = 0
            rc = run_backup_all(paths)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

        # beta backed up; alpha never made it past the lock check.
        called_names = [c.args[0] for c in mock_backup.call_args_list]
        assert "beta" in called_names
        assert "alpha" not in called_names

        # Pushover alert was triggered for alpha.
        mock_notify.assert_called_once()
        notified = mock_notify.call_args[0][1]
        assert notified == ["alpha"]

        # Exit code is 1 because of the persistent skip.
        assert rc == 1

    @patch("boxmunge.commands.backup_cmd._notify_persistent_locks")
    @patch("boxmunge.commands.backup_cmd.run_backup")
    def test_locked_project_recovers_within_budget(
        self, mock_backup: MagicMock, mock_notify: MagicMock,
        paths: BoxPaths, monkeypatch,
    ) -> None:
        """If the lock is released during the retry window, backup succeeds
        and no Pushover alert fires."""
        self._setup_two_projects(paths)
        monkeypatch.setattr(backup_cmd, "_LOCK_RETRY_BUDGET_SECONDS", 1.0)
        monkeypatch.setattr(backup_cmd, "_LOCK_RETRY_INTERVAL_SECONDS", 0.05)

        # Hold alpha's lock briefly, release in a thread.
        fd = self._hold_project_lock(paths, "alpha")
        import threading, time as _time
        def _release_after_short_delay():
            _time.sleep(0.15)
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        threading.Thread(target=_release_after_short_delay, daemon=True).start()

        mock_backup.return_value = 0
        rc = run_backup_all(paths)

        # Both projects eventually backed up.
        called_names = sorted(c.args[0] for c in mock_backup.call_args_list)
        assert "alpha" in called_names
        assert "beta" in called_names

        mock_notify.assert_not_called()
        assert rc == 0

    @patch("boxmunge.commands.backup_cmd._notify_persistent_locks")
    @patch("boxmunge.commands.backup_cmd.run_backup")
    def test_real_failure_not_treated_as_lock_skip(
        self, mock_backup: MagicMock, mock_notify: MagicMock,
        paths: BoxPaths,
    ) -> None:
        """A non-zero return from run_backup is a real failure, not a lock-skip.
        Pushover lock-skip alert must NOT fire for ordinary backup failures."""
        self._setup_two_projects(paths)
        # alpha "fails" with rc=1 (e.g. dump error); beta succeeds.
        def side(name, paths_, _lock_held=False):
            return 1 if name == "alpha" else 0
        mock_backup.side_effect = side

        rc = run_backup_all(paths)

        mock_notify.assert_not_called()
        assert rc == 1

    @patch("boxmunge.commands.backup_cmd.log_operation")
    @patch("boxmunge.commands.backup_cmd._notify_persistent_locks")
    @patch("boxmunge.commands.backup_cmd.run_backup")
    def test_first_pass_lock_logs_retry_intent(
        self, mock_backup: MagicMock, mock_notify: MagicMock,
        mock_log_op: MagicMock,
        paths: BoxPaths, monkeypatch,
    ) -> None:
        """Audit E-NEW-4: first-pass lock skip emits a structured log line
        ("locked, retrying") so the forensic trail isn't only on stdout.
        """
        self._setup_two_projects(paths)
        monkeypatch.setattr(backup_cmd, "_LOCK_RETRY_BUDGET_SECONDS", 0.1)
        monkeypatch.setattr(backup_cmd, "_LOCK_RETRY_INTERVAL_SECONDS", 0.05)

        fd = self._hold_project_lock(paths, "alpha")
        try:
            mock_backup.return_value = 0
            run_backup_all(paths)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

        retry_msgs = [
            c for c in mock_log_op.call_args_list
            if c.args[1] == "locked, retrying" and c.kwargs.get("project") == "alpha"
        ]
        assert len(retry_msgs) == 1, mock_log_op.call_args_list

    @patch("boxmunge.commands.backup_cmd.log_operation")
    @patch("boxmunge.commands.backup_cmd._notify_persistent_locks")
    @patch("boxmunge.commands.backup_cmd.run_backup")
    def test_retry_success_emits_log_entry(
        self, mock_backup: MagicMock, mock_notify: MagicMock,
        mock_log_op: MagicMock,
        paths: BoxPaths, monkeypatch,
    ) -> None:
        """Audit E-NEW-4: retry success emits "backup completed after retry"."""
        self._setup_two_projects(paths)
        monkeypatch.setattr(backup_cmd, "_LOCK_RETRY_BUDGET_SECONDS", 1.0)
        monkeypatch.setattr(backup_cmd, "_LOCK_RETRY_INTERVAL_SECONDS", 0.05)

        # Hold alpha briefly then release in a thread.
        fd = self._hold_project_lock(paths, "alpha")
        import threading
        import time as _time

        def _release():
            _time.sleep(0.15)
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        threading.Thread(target=_release, daemon=True).start()

        mock_backup.return_value = 0
        run_backup_all(paths)

        retry_completed = [
            c for c in mock_log_op.call_args_list
            if c.args[1] == "backup completed after retry"
            and c.kwargs.get("project") == "alpha"
        ]
        assert len(retry_completed) == 1, mock_log_op.call_args_list


class TestNotifyPersistentLocks:
    """Audit D-NEW-3: distinguish Pushover-sent vs Pushover-not-configured."""

    @patch("boxmunge.commands.backup_cmd.log_operation")
    @patch("boxmunge.commands.backup_cmd.log_warning")
    @patch("boxmunge.pushover.send_notification")
    @patch("boxmunge.commands.backup_cmd.load_config")
    def test_pushover_sent_logs_operation(
        self, mock_load: MagicMock, mock_send: MagicMock,
        mock_log_warn: MagicMock, mock_log_op: MagicMock,
        paths: BoxPaths,
    ) -> None:
        from boxmunge.commands.backup_cmd import _notify_persistent_locks
        mock_load.return_value = {
            "pushover": {"user_key": "u", "app_token": "t"},
        }
        mock_send.return_value = True
        _notify_persistent_locks(paths, ["alpha"])
        sent_logs = [
            c for c in mock_log_op.call_args_list
            if "Pushover sent" in c.args[1]
        ]
        assert len(sent_logs) == 1
        # No warning when alert was actually delivered.
        warn_logs = [
            c for c in mock_log_warn.call_args_list
            if "alert dropped" in c.args[1]
        ]
        assert warn_logs == []

    @patch("boxmunge.commands.backup_cmd.log_operation")
    @patch("boxmunge.commands.backup_cmd.log_warning")
    @patch("boxmunge.pushover.send_notification")
    @patch("boxmunge.commands.backup_cmd.load_config")
    def test_pushover_unconfigured_logs_warning(
        self, mock_load: MagicMock, mock_send: MagicMock,
        mock_log_warn: MagicMock, mock_log_op: MagicMock,
        paths: BoxPaths,
    ) -> None:
        from boxmunge.commands.backup_cmd import _notify_persistent_locks
        # Empty pushover config -> send_notification returns False.
        mock_load.return_value = {"pushover": {}}
        mock_send.return_value = False
        _notify_persistent_locks(paths, ["alpha", "beta"])

        dropped = [
            c for c in mock_log_warn.call_args_list
            if "alert dropped" in c.args[1]
        ]
        assert len(dropped) == 1
        assert "Pushover not configured" in dropped[0].args[1]
        # No "Pushover sent" log entry on the unconfigured branch.
        sent_logs = [
            c for c in mock_log_op.call_args_list
            if "Pushover sent" in c.args[1]
        ]
        assert sent_logs == []


class TestListSnapshots:
    def test_lists_existing_snapshots(self, paths: BoxPaths) -> None:
        _setup_project(paths, MANIFEST_WITH_BACKUP)
        bdir = paths.project_backups("myapp")
        (bdir / "myapp-2026-03-28T020000.tar.gz.age").write_bytes(b"a")
        (bdir / "myapp-2026-03-29T020000.tar.gz.age").write_bytes(b"b")

        snaps = list_snapshots(paths, "myapp")
        assert len(snaps) == 2

    def test_empty_when_no_backups(self, paths: BoxPaths) -> None:
        _setup_project(paths, MANIFEST_WITH_BACKUP)
        snaps = list_snapshots(paths, "myapp")
        assert snaps == []
