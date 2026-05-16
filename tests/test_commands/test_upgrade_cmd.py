# SPDX-License-Identifier: Apache-2.0
"""Tests for upgrade_cmd --dry-run and --apply flags."""

from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.paths import BoxPaths
from boxmunge.version import write_installed_version
from boxmunge.commands.upgrade_cmd import run_upgrade


def _setup_paths(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects", "state/deploy", "stashes", "logs",
              "caddy/sites", "upgrade-state"]:
        (paths.root / d).mkdir(parents=True)
    paths.config_file.write_text("hostname: test\nadmin_email: t@t\n")
    write_installed_version(paths, "0.2.0", "abc1234")
    return paths


class TestDryRun:
    def test_dry_run_returns_zero_with_no_projects(self, tmp_path):
        paths = _setup_paths(tmp_path)
        result = run_upgrade(paths, dry_run=True)
        assert result == 0

    def test_dry_run_does_not_write_version_file(self, tmp_path):
        paths = _setup_paths(tmp_path)
        original = paths.version_file.read_text()
        run_upgrade(paths, dry_run=True)
        assert paths.version_file.read_text() == original

    def test_dry_run_does_not_create_stash(self, tmp_path):
        paths = _setup_paths(tmp_path)
        run_upgrade(paths, dry_run=True)
        stashes = list(paths.stashes.glob("*.tar.gz"))
        assert len(stashes) == 0

    @patch("boxmunge.commands.upgrade_cmd.caddy_reload")
    def test_dry_run_does_not_reload_caddy(self, mock_reload, tmp_path):
        paths = _setup_paths(tmp_path)
        run_upgrade(paths, dry_run=True)
        mock_reload.assert_not_called()

    @patch("boxmunge.commands.upgrade_cmd.compose_up")
    def test_dry_run_does_not_restart_projects(self, mock_up, tmp_path):
        paths = _setup_paths(tmp_path)
        run_upgrade(paths, dry_run=True)
        mock_up.assert_not_called()

    def test_dry_run_does_not_modify_manifests(self, tmp_path):
        paths = _setup_paths(tmp_path)
        # Create a project with an old schema version
        project_dir = paths.project_dir("myapp")
        project_dir.mkdir(parents=True)
        import yaml
        (project_dir / "manifest.yml").write_text(yaml.dump({
            "schema_version": 1, "project": "myapp",
            "source": "bundle", "hosts": ["myapp.test"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }))
        original = (project_dir / "manifest.yml").read_text()
        run_upgrade(paths, dry_run=True)
        assert (project_dir / "manifest.yml").read_text() == original


class TestApplyMode:
    @patch("boxmunge.commands.upgrade_cmd.caddy_reload")
    def test_apply_skips_stash(self, mock_reload, tmp_path):
        paths = _setup_paths(tmp_path)
        result = run_upgrade(paths, apply_only=True)
        assert result == 0
        stashes = list(paths.stashes.glob("*.tar.gz"))
        assert len(stashes) == 0


class TestRestartRespectsLock:
    """4b: _restart_projects must skip projects whose project_lock is held."""

    def _make_project(self, paths: BoxPaths, name: str) -> None:
        import yaml
        pdir = paths.project_dir(name)
        pdir.mkdir(parents=True)
        (pdir / "manifest.yml").write_text(yaml.dump({
            "schema_version": 2, "project": name,
            "source": "bundle", "hosts": [f"{name}.test"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }))

    @patch("boxmunge.commands.upgrade_cmd.compose_up")
    def test_locked_project_is_skipped_not_raised(
        self, mock_up, tmp_path
    ) -> None:
        from boxmunge.commands.upgrade_cmd import _restart_projects
        from boxmunge.fileutil import project_lock

        paths = _setup_paths(tmp_path)
        self._make_project(paths, "alpha")
        self._make_project(paths, "beta")

        # Hold alpha's lock from this thread (NB: project_lock is non-blocking).
        # Use a separate thread so the same-process flock semantics still apply
        # at fd level (advisory POSIX locks are per-process by file descriptor).
        # Simpler: open the same lock file in a different fd before calling.
        import os, fcntl
        alpha_lock = paths.project_lock_file("alpha")
        alpha_lock.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(alpha_lock), os.O_CREAT | os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            succeeded, failed, skipped = _restart_projects(paths)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

        assert "alpha" in skipped
        assert "beta" in succeeded
        assert failed == []
        # compose_up was only called for beta.
        assert mock_up.call_count == 1

    @patch("boxmunge.commands.upgrade_cmd.compose_up")
    def test_no_locks_held_returns_all_succeeded(
        self, mock_up, tmp_path
    ) -> None:
        from boxmunge.commands.upgrade_cmd import _restart_projects

        paths = _setup_paths(tmp_path)
        self._make_project(paths, "alpha")
        self._make_project(paths, "beta")

        succeeded, failed, skipped = _restart_projects(paths)

        assert sorted(succeeded) == ["alpha", "beta"]
        assert failed == []
        assert skipped == []


class TestLockSkipPushoverNotification:
    """D-NEW-1: when _restart_projects skips locked projects during upgrade,
    a Pushover notification must fire so non-interactive operators see it."""

    def _make_project(self, paths: BoxPaths, name: str) -> None:
        import yaml
        pdir = paths.project_dir(name)
        pdir.mkdir(parents=True)
        # Use CURRENT_SCHEMA_VERSION + a valid id so the upgrade flow's
        # post-migration validation pass doesn't fail on the fixture.
        # This test exercises lock semantics, not migration.
        from boxmunge.manifest import CURRENT_SCHEMA_VERSION
        (pdir / "manifest.yml").write_text(yaml.dump({
            "schema_version": CURRENT_SCHEMA_VERSION, "project": name,
            "id": f"01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "source": "bundle", "hosts": [f"{name}.test"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }))

    @patch("boxmunge.commands.upgrade_cmd.caddy_reload")
    @patch("boxmunge.commands.upgrade_cmd.compose_up")
    @patch("boxmunge.pushover.send_notification")
    def test_pushover_fires_when_apply_skips_locked_project(
        self, mock_pushover, mock_up, mock_reload, tmp_path
    ) -> None:
        # Configure pushover so the wrapper actually attempts to send
        paths = _setup_paths(tmp_path)
        paths.config_file.write_text(
            "hostname: test\nadmin_email: t@t\n"
            "pushover:\n  user_key: u\n  app_token: t\n"
        )
        self._make_project(paths, "alpha")
        self._make_project(paths, "beta")

        import os, fcntl
        alpha_lock = paths.project_lock_file("alpha")
        alpha_lock.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(alpha_lock), os.O_CREAT | os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            result = run_upgrade(paths, apply_only=True)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

        assert result == 0
        # Exactly one Pushover call, summarising the skipped project
        assert mock_pushover.call_count == 1
        call_args = mock_pushover.call_args
        # send_notification(user_key, app_token, title, message)
        title = call_args.args[2] if len(call_args.args) >= 3 else call_args.kwargs.get("title", "")
        message = call_args.args[3] if len(call_args.args) >= 4 else call_args.kwargs.get("message", "")
        assert "skipped" in title.lower()
        assert "alpha" in message

    @patch("boxmunge.commands.upgrade_cmd.caddy_reload")
    @patch("boxmunge.commands.upgrade_cmd.compose_up")
    @patch("boxmunge.pushover.send_notification")
    def test_pushover_silent_when_no_skips(
        self, mock_pushover, mock_up, mock_reload, tmp_path
    ) -> None:
        paths = _setup_paths(tmp_path)
        paths.config_file.write_text(
            "hostname: test\nadmin_email: t@t\n"
            "pushover:\n  user_key: u\n  app_token: t\n"
        )
        self._make_project(paths, "alpha")

        result = run_upgrade(paths, apply_only=True)
        assert result == 0
        # No skips -> no notification
        mock_pushover.assert_not_called()


class TestSkipsQuarantined:
    """Wave 1: upgrade must NOT silently un-quarantine projects.

    `_regenerate_configs` MUST re-render the maintenance Caddy fragment
    (not the normal site config) for a quarantined project, and
    `_restart_projects` MUST skip them entirely.
    """

    def _make_project(self, paths: BoxPaths, name: str) -> None:
        import yaml
        pdir = paths.project_dir(name)
        pdir.mkdir(parents=True)
        (pdir / "manifest.yml").write_text(yaml.dump({
            "schema_version": 2, "project": name,
            "source": "bundle", "hosts": [f"{name}.test"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }))
        (pdir / "compose.yml").write_text(
            "services:\n  web:\n    image: nginx:1.25\n"
        )

    def _quarantine(self, paths: BoxPaths, name: str) -> None:
        paths.project_quarantine_state(name).parent.mkdir(
            parents=True, exist_ok=True,
        )
        paths.project_quarantine_state(name).write_text("{}")

    @patch("boxmunge.commands.upgrade_cmd.compose_up")
    def test_restart_skips_quarantined_project(self, mock_up, tmp_path):
        from boxmunge.commands.upgrade_cmd import _restart_projects
        paths = _setup_paths(tmp_path)
        self._make_project(paths, "alpha")
        self._make_project(paths, "beta")
        self._quarantine(paths, "alpha")

        succeeded, failed, skipped = _restart_projects(paths)

        # alpha was quarantined, so compose_up MUST NOT have been called
        # for it — only beta should have been started.
        assert "alpha" not in succeeded
        assert "beta" in succeeded
        assert failed == []
        # Quarantined projects are not lock-skipped — they're a different
        # category. They MUST NOT appear in skipped_locked either; the
        # caller's Pushover fires for "locked" only.
        assert "alpha" not in skipped
        assert mock_up.call_count == 1

    @patch("boxmunge.commands.upgrade_cmd.compose_up")
    def test_restart_logs_quarantine_skip(self, mock_up, tmp_path):
        from boxmunge.commands.upgrade_cmd import _restart_projects
        paths = _setup_paths(tmp_path)
        self._make_project(paths, "alpha")
        self._quarantine(paths, "alpha")

        with patch("boxmunge.commands.upgrade_cmd.log_operation") as mock_log:
            _restart_projects(paths)

        # The skip MUST be logged with the upgrade component and project.
        skip_logs = [
            c for c in mock_log.call_args_list
            if c.args[0] == "upgrade"
            and "quarantine" in c.args[1].lower()
            and c.kwargs.get("project") == "alpha"
        ]
        assert len(skip_logs) == 1, mock_log.call_args_list

    def test_regen_renders_maintenance_for_quarantined(self, tmp_path):
        from boxmunge.commands.upgrade_cmd import _regenerate_configs
        paths = _setup_paths(tmp_path)
        self._make_project(paths, "alpha")
        self._quarantine(paths, "alpha")

        # Pre-existing site config from a prior deploy (we want to be sure
        # _regenerate_configs OVERWRITES with the maintenance fragment, not
        # the normal one).
        site_conf = paths.project_caddy_site("alpha")
        site_conf.parent.mkdir(parents=True, exist_ok=True)
        site_conf.write_text("# pre-existing normal config\n")

        processed = _regenerate_configs(paths)

        # alpha was quarantined, so the normal-regen path must have been
        # skipped (alpha not in processed).
        assert "alpha" not in processed
        # The maintenance fragment must be on disk now.
        content = site_conf.read_text()
        assert "503" in content
        assert "alpha.test" in content

    def test_regen_logs_quarantine_skip(self, tmp_path):
        from boxmunge.commands.upgrade_cmd import _regenerate_configs
        paths = _setup_paths(tmp_path)
        self._make_project(paths, "alpha")
        self._quarantine(paths, "alpha")

        with patch("boxmunge.commands.upgrade_cmd.log_operation") as mock_log:
            _regenerate_configs(paths)

        skip_logs = [
            c for c in mock_log.call_args_list
            if c.args[0] == "upgrade"
            and "quarantine" in c.args[1].lower()
            and c.kwargs.get("project") == "alpha"
        ]
        assert len(skip_logs) == 1, mock_log.call_args_list

    def test_regen_does_not_call_prepare_caddy_for_quarantined(self, tmp_path):
        """Defensive: prepare_caddy_config / prepare_compose_override
        MUST NOT be invoked for a quarantined project — the maintenance
        fragment is hand-rendered."""
        from boxmunge.commands.upgrade_cmd import _regenerate_configs
        paths = _setup_paths(tmp_path)
        self._make_project(paths, "alpha")
        self._quarantine(paths, "alpha")

        with patch(
            "boxmunge.commands.upgrade_cmd.prepare_caddy_config",
        ) as mock_caddy, patch(
            "boxmunge.commands.upgrade_cmd.prepare_compose_override",
        ) as mock_overlay:
            _regenerate_configs(paths)

        mock_caddy.assert_not_called()
        mock_overlay.assert_not_called()


class TestCvePolicyValidatorWiring:
    """C-1 regression: upgrade's `_regenerate_configs` must pass the
    manifest's `security` block as `cve_policy` to validate_user_compose.
    Mirrors the deploy.py canonical test in
    test_deploy.py::TestCvePolicyValidatorWiring.

    Test bypasses the quarantine-check branch (no quarantine state set up)
    so the validator path actually runs.
    """

    def _make_project_with_security(
        self, paths: BoxPaths, name: str = "alpha",
    ) -> None:
        import yaml
        pdir = paths.project_dir(name)
        pdir.mkdir(parents=True)
        (pdir / "manifest.yml").write_text(yaml.dump({
            "schema_version": 2, "project": name,
            "source": "bundle", "hosts": [f"{name}.test"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
            "security": {"posture": "strict"},
        }))
        (pdir / "compose.yml").write_text(
            "services:\n  web:\n    image: nginx:1.25\n    read_only: true\n"
        )

    @patch("boxmunge.commands.upgrade_cmd.prepare_compose_override")
    @patch("boxmunge.commands.upgrade_cmd.prepare_caddy_config")
    def test_regen_passes_security_block_as_cve_policy(
        self, _caddy, _overlay, tmp_path,
    ) -> None:
        from boxmunge.commands.upgrade_cmd import _regenerate_configs

        paths = _setup_paths(tmp_path)
        self._make_project_with_security(paths, "alpha")
        # Sanity: alpha is NOT quarantined — the validator path runs.

        with patch(
            "boxmunge.commands.upgrade_cmd.validate_user_compose",
        ) as mock_validate:
            _regenerate_configs(paths)

        # validate_user_compose must have been called for alpha and the
        # manifest's `security` block must have been forwarded as cve_policy.
        assert mock_validate.called, "validate_user_compose was not called"
        kwargs = mock_validate.call_args.kwargs
        assert kwargs.get("cve_policy") == {"posture": "strict"}, (
            f"validate_user_compose called with cve_policy="
            f"{kwargs.get('cve_policy')!r}; expected manifest's security block"
        )


class TestArgParsing:
    """cmd_upgrade arg parsing — previously silently ignored unknown args."""

    def test_help_flag_prints_usage_and_exits_zero(self, capsys):
        from boxmunge.commands.upgrade_cmd import cmd_upgrade
        with pytest.raises(SystemExit) as exc:
            cmd_upgrade(["--help"])
        assert exc.value.code == 0
        assert "Usage:" in capsys.readouterr().out

    def test_short_help_flag_prints_usage(self, capsys):
        from boxmunge.commands.upgrade_cmd import cmd_upgrade
        with pytest.raises(SystemExit) as exc:
            cmd_upgrade(["-h"])
        assert exc.value.code == 0

    def test_unknown_arg_exits_2_with_usage(self, capsys):
        from boxmunge.commands.upgrade_cmd import cmd_upgrade
        with pytest.raises(SystemExit) as exc:
            cmd_upgrade(["--target", "0.3.5"])
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "unknown argument" in err
        assert "Usage:" in err

    def test_dry_run_and_apply_mutually_exclusive(self, capsys):
        from boxmunge.commands.upgrade_cmd import cmd_upgrade
        with pytest.raises(SystemExit) as exc:
            cmd_upgrade(["--dry-run", "--apply"])
        assert exc.value.code == 2
