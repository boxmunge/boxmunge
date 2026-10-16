"""Lifecycle commands and container-update take the project lock (audit C-03, B-05).

Each test holds the real project flock from another process, as a concurrent
deploy, scan, or health tick would, and checks the operation refuses without
touching compose or Caddy. Where a gating check (paused, quarantined,
monitor-stopped) decides whether to act, the check must run while the lock is
held, so a concurrent quarantine cannot land between check and action.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import yaml

from boxmunge.backup import BackupKind
from boxmunge.paths import BoxPaths
from boxmunge.state import write_state
from tests.lock_holder import hold_project_lock, project_lock_is_held

NAME = "myapp"


def _setup(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", f"projects/{NAME}", "state/deploy", "state/health",
              "caddy/sites", "logs"]:
        (paths.root / d).mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n")
    (paths.project_dir(NAME) / "manifest.yml").write_text(yaml.dump({
        "schema_version": 1, "id": "01TEST", "project": NAME,
        "source": "bundle", "hosts": [f"{NAME}.test"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))
    (paths.project_dir(NAME) / "compose.yml").write_text(
        "services:\n  web:\n    image: nginx:1.25\n"
    )
    paths.project_caddy_site(NAME).write_text("# site\n")
    return paths


def _quarantine(paths: BoxPaths) -> None:
    write_state(paths.project_quarantine_state(NAME), {"cve_id": "CVE-2099-0001"})


class _Recorder:
    """Records each call and whether the project lock was held at the time."""

    def __init__(self, paths: BoxPaths, result=None):
        self.paths = paths
        self.result = result
        self.calls: list[bool] = []

    def __call__(self, *args, **kwargs):
        self.calls.append(project_lock_is_held(NAME, self.paths))
        return self.result


# ---------------------------------------------------------------------------
# pause
# ---------------------------------------------------------------------------

class TestPauseLock:
    @patch("boxmunge.commands.pause_cmd.compose_stop")
    @patch("boxmunge.commands.pause_cmd.caddy_reload")
    def test_refuses_while_lock_held(self, mock_reload, mock_stop, tmp_path, capsys):
        from boxmunge.commands.pause_cmd import run_pause
        from boxmunge.pause import is_paused
        paths = _setup(tmp_path)
        with hold_project_lock(NAME, paths):
            rc = run_pause(NAME, paths, yes=True)
        assert rc == 1
        assert "Another operation is in progress" in capsys.readouterr().err
        assert not is_paused(NAME, paths)
        mock_reload.assert_not_called()
        mock_stop.assert_not_called()
        assert "# site" in paths.project_caddy_site(NAME).read_text()

    def test_mutations_and_gate_run_under_lock(self, tmp_path):
        from boxmunge.commands import pause_cmd
        from boxmunge.pause import is_paused as real_is_paused
        paths = _setup(tmp_path)
        gate = _Recorder(paths)
        reload_rec, stop_rec = _Recorder(paths), _Recorder(paths)

        def recording_is_paused(name, p):
            gate(name, p)
            return real_is_paused(name, p)

        with patch.object(pause_cmd, "is_paused", recording_is_paused), \
             patch.object(pause_cmd, "caddy_reload", reload_rec), \
             patch.object(pause_cmd, "compose_stop", stop_rec):
            assert pause_cmd.run_pause(NAME, paths, yes=True) == 0
        assert gate.calls[-1] is True, "already-paused check must run under the lock"
        assert reload_rec.calls == [True]
        assert stop_rec.calls == [True]


# ---------------------------------------------------------------------------
# resume
# ---------------------------------------------------------------------------

def _resume_patches(paths: BoxPaths):
    from boxmunge.commands import resume_cmd
    return [
        patch.object(resume_cmd, "compose_pull", _Recorder(paths)),
        patch.object(resume_cmd, "compose_up", _Recorder(paths)),
        patch.object(resume_cmd, "caddy_reload", _Recorder(paths)),
        patch.object(resume_cmd, "prepare_caddy_config"),
        patch.object(resume_cmd, "prepare_compose_override"),
        patch.object(resume_cmd, "validate_user_compose"),
        patch.object(resume_cmd, "run_smoke", return_value=(True, "")),
    ]


class TestResumeLock:
    def test_refuses_while_lock_held(self, tmp_path, capsys):
        from boxmunge.commands import resume_cmd
        from boxmunge.pause import is_paused, write_paused_state
        paths = _setup(tmp_path)
        write_paused_state(NAME, paths)
        ps = _resume_patches(paths)
        mocks = [p.start() for p in ps]
        try:
            with hold_project_lock(NAME, paths):
                rc = resume_cmd.run_resume(NAME, paths, yes=True)
        finally:
            for p in ps:
                p.stop()
        assert rc == 1
        assert "Another operation is in progress" in capsys.readouterr().err
        assert is_paused(NAME, paths)
        assert mocks[0].calls == [] and mocks[1].calls == [] and mocks[2].calls == []

    def test_mutations_and_gates_run_under_lock(self, tmp_path):
        from boxmunge.commands import resume_cmd
        from boxmunge.lifecycle import is_blocked as real_is_blocked
        from boxmunge.pause import write_paused_state
        paths = _setup(tmp_path)
        write_paused_state(NAME, paths)
        gate = _Recorder(paths)

        def recording_is_blocked(name, p):
            gate(name, p)
            return real_is_blocked(name, p)

        ps = _resume_patches(paths)
        mocks = [p.start() for p in ps]
        try:
            with patch.object(resume_cmd, "is_blocked", recording_is_blocked):
                assert resume_cmd.run_resume(NAME, paths, yes=True) == 0
        finally:
            for p in ps:
                p.stop()
        assert gate.calls[-1] is True, "quarantine check must run under the lock"
        pull, up, reload_ = mocks[0], mocks[1], mocks[2]
        assert pull.calls == [True] and up.calls == [True] and reload_.calls == [True]

    def test_quarantine_landing_after_prompt_is_honoured(self, tmp_path):
        """A quarantine written between the pre-check and the lock wins."""
        from boxmunge.commands import resume_cmd
        from boxmunge.pause import write_paused_state
        paths = _setup(tmp_path)
        write_paused_state(NAME, paths)

        def quarantine_then_confirm(_prompt):
            _quarantine(paths)
            return "y"

        ps = _resume_patches(paths)
        mocks = [p.start() for p in ps]
        try:
            with patch("builtins.input", quarantine_then_confirm):
                rc = resume_cmd.run_resume(NAME, paths, yes=False)
        finally:
            for p in ps:
                p.stop()
        assert rc == 1
        assert mocks[1].calls == [], "compose_up must not run on a quarantined project"


# ---------------------------------------------------------------------------
# recover
# ---------------------------------------------------------------------------

def _recover_patches(paths: BoxPaths):
    from boxmunge.commands import recover_cmd
    return [
        patch.object(recover_cmd, "compose_up", _Recorder(paths)),
        patch.object(recover_cmd, "caddy_reload", _Recorder(paths)),
        patch.object(recover_cmd, "prepare_caddy_config"),
        patch.object(recover_cmd, "prepare_compose_override"),
        patch.object(recover_cmd, "run_smoke", return_value=(True, "")),
    ]


class TestRecoverLock:
    def test_refuses_while_lock_held(self, tmp_path, capsys):
        from boxmunge.commands import recover_cmd
        from boxmunge.state import read_state
        paths = _setup(tmp_path)
        write_state(paths.project_health_state(NAME), {"status": "critical_stopped"})
        ps = _recover_patches(paths)
        mocks = [p.start() for p in ps]
        try:
            with hold_project_lock(NAME, paths):
                rc = recover_cmd.run_recover(NAME, paths, yes=True)
        finally:
            for p in ps:
                p.stop()
        assert rc == 1
        assert "Another operation is in progress" in capsys.readouterr().err
        assert mocks[0].calls == [] and mocks[1].calls == []
        assert read_state(paths.project_health_state(NAME))["status"] == "critical_stopped"

    def test_mutations_and_gates_run_under_lock(self, tmp_path):
        from boxmunge.commands import recover_cmd
        from boxmunge.lifecycle import is_blocked as real_is_blocked
        paths = _setup(tmp_path)
        write_state(paths.project_health_state(NAME), {"status": "critical_stopped"})
        gate = _Recorder(paths)

        def recording_is_blocked(name, p):
            gate(name, p)
            return real_is_blocked(name, p)

        ps = _recover_patches(paths)
        mocks = [p.start() for p in ps]
        try:
            with patch.object(recover_cmd, "is_blocked", recording_is_blocked):
                assert recover_cmd.run_recover(NAME, paths, yes=True) == 0
        finally:
            for p in ps:
                p.stop()
        assert gate.calls[-1] is True, "pause/quarantine check must run under the lock"
        assert mocks[0].calls == [True] and mocks[1].calls == [True]


# ---------------------------------------------------------------------------
# project-delete
# ---------------------------------------------------------------------------

class TestProjectDeleteLock:
    @patch("boxmunge.commands.project_delete_cmd.compose_down")
    @patch("boxmunge.commands.project_delete_cmd.caddy_reload")
    def test_refuses_while_lock_held(self, mock_reload, mock_down, tmp_path, capsys):
        from boxmunge.commands.project_delete_cmd import run_project_delete
        paths = _setup(tmp_path)
        with hold_project_lock(NAME, paths):
            rc = run_project_delete(NAME, paths, yes=True)
        assert rc == 1
        assert "Another operation is in progress" in capsys.readouterr().err
        assert paths.project_dir(NAME).exists()
        assert paths.project_caddy_site(NAME).exists()
        mock_down.assert_not_called()
        mock_reload.assert_not_called()

    def test_teardown_runs_under_lock(self, tmp_path):
        from boxmunge.commands import project_delete_cmd
        paths = _setup(tmp_path)
        down_rec, reload_rec = _Recorder(paths), _Recorder(paths)
        with patch.object(project_delete_cmd, "compose_down", down_rec), \
             patch.object(project_delete_cmd, "caddy_reload", reload_rec):
            assert project_delete_cmd.run_project_delete(NAME, paths, yes=True) == 0
        assert down_rec.calls == [True]
        assert reload_rec.calls == [True]
        assert not paths.project_dir(NAME).exists()


# ---------------------------------------------------------------------------
# container-update
# ---------------------------------------------------------------------------

def _cu_target(paths: BoxPaths, *, has_backup: bool = False, strategy="leave_broken"):
    from boxmunge.container_update_targets import UpdateTarget
    return UpdateTarget(
        name=NAME, project_dir=paths.project_dir(NAME),
        compose_files=["compose.yml"], strategy=strategy, has_backup=has_backup,
    )


class TestContainerUpdateLock:
    def test_refuses_while_lock_held(self, tmp_path):
        import boxmunge.container_update as cu
        paths = _setup(tmp_path)
        pull, up, backup = _Recorder(paths), _Recorder(paths), _Recorder(paths, 0)
        with patch.object(cu, "compose_pull", pull), \
             patch.object(cu, "compose_up", up), \
             patch.object(cu, "run_backup", backup), \
             patch.object(cu, "detect_image_changes", return_value={"web": "sha256:new"}), \
             patch.object(cu, "_wait_healthy", return_value=(True, [])):
            with hold_project_lock(NAME, paths):
                result = cu.update_target(paths, _cu_target(paths, has_backup=True))
        assert result["status"] != "succeeded"
        assert "lock" in (result["reason"] or "")
        assert pull.calls == [] and up.calls == [] and backup.calls == []

    def test_whole_update_runs_under_lock(self, tmp_path):
        """Backup, pull, recreate, health wait, and rollback all hold the lock."""
        import boxmunge.container_update as cu
        from boxmunge.lifecycle import is_blocked as real_is_blocked
        paths = _setup(tmp_path)
        gate = _Recorder(paths)

        def recording_is_blocked(name, p):
            gate(name, p)
            return real_is_blocked(name, p)

        backup_kwargs: list[dict] = []
        backup_rec = _Recorder(paths, 0)

        def fake_backup(name, p, **kwargs):
            backup_kwargs.append(kwargs)
            return backup_rec(name, p)

        pull, up, tag = _Recorder(paths), _Recorder(paths), _Recorder(paths)
        health = _Recorder(paths, (False, ["web"]))
        with patch.object(cu, "is_blocked", recording_is_blocked), \
             patch.object(cu, "run_backup", fake_backup), \
             patch.object(cu, "compose_pull", pull), \
             patch.object(cu, "compose_up", up), \
             patch.object(cu, "tag_image", tag), \
             patch.object(cu, "_wait_healthy", health), \
             patch.object(cu, "detect_image_changes", return_value={"web": "sha256:new"}):
            result = cu.update_target(
                paths, _cu_target(paths, has_backup=True, strategy="rollback_to_previous"),
            )
        assert result["rollback_attempted"] is True
        assert gate.calls == [True], "quarantine/pause check must run under the lock"
        assert backup_rec.calls == [True]
        assert backup_kwargs == [{"kind": BackupKind.PREUPDATE, "_lock_held": True}]
        assert pull.calls == [True]
        assert up.calls == [True, True]  # recreate + rollback recreate
        assert tag.calls == [True]
        assert health.calls == [True, True]
        assert not project_lock_is_held(NAME, paths), "lock released afterwards"

    def test_quarantine_is_rechecked_under_lock(self, tmp_path):
        """A quarantine that lands while the caller was waiting is honoured."""
        import boxmunge.container_update as cu
        paths = _setup(tmp_path)
        _quarantine(paths)
        pull, up = _Recorder(paths), _Recorder(paths)
        with patch.object(cu, "compose_pull", pull), patch.object(cu, "compose_up", up):
            result = cu.update_target(paths, _cu_target(paths))
        assert result["status"] == "quarantined"
        assert pull.calls == [] and up.calls == []
