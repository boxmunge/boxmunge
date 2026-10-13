# SPDX-License-Identifier: Apache-2.0
"""C-05: an upgrade keeps paused projects on the maintenance page, and
`upgrade --dry-run` writes nothing at all."""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
from unittest.mock import patch

import yaml

from boxmunge.commands.upgrade_cmd import run_upgrade
from boxmunge.commands.upgrade_steps import regenerate_configs
from boxmunge.manifest import CURRENT_SCHEMA_VERSION
from boxmunge.pause import render_maintenance_caddy_config, write_paused_state
from boxmunge.paths import BoxPaths
from boxmunge.version import write_installed_version


def _setup(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects", "state/deploy", "stashes", "logs",
              "caddy/sites", "upgrade-state"]:
        (paths.root / d).mkdir(parents=True)
    paths.config_file.write_text("hostname: test\nadmin_email: t@t\n")
    write_installed_version(paths, "0.2.0", "abc1234")
    return paths


def _project(paths: BoxPaths, name: str, schema: int = CURRENT_SCHEMA_VERSION) -> None:
    pdir = paths.project_dir(name)
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(yaml.dump({
        "schema_version": schema, "project": name,
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle", "hosts": [f"{name}.test"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))
    (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx:1.25\n")
    paths.project_caddy_site(name).write_text(f"# live config for {name}\n")


def _pause(paths: BoxPaths, name: str) -> None:
    write_paused_state(name, paths, reason="maintenance window")
    paths.project_caddy_site(name).write_text(
        render_maintenance_caddy_config([f"{name}.test"]))


def _quarantine(paths: BoxPaths, name: str) -> None:
    paths.project_quarantine_state(name).parent.mkdir(parents=True, exist_ok=True)
    paths.project_quarantine_state(name).write_text("{}")


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(root)): p.read_bytes()
        for p in sorted(root.rglob("*")) if p.is_file()
    }


class TestPausedProjectsKeepMaintenancePage:
    def test_regen_keeps_paused_maintenance_page(self, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        _project(paths, "alpha")
        _pause(paths, "alpha")
        regenerate_configs(paths)
        content = paths.project_caddy_site("alpha").read_text()
        assert "status 503" in content
        assert "reverse_proxy" not in content

    def test_regen_does_not_regenerate_paused_overlay(self, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        _project(paths, "alpha")
        _pause(paths, "alpha")
        with patch("boxmunge.commands.upgrade_steps.prepare_caddy_config") as caddy, \
             patch("boxmunge.commands.upgrade_steps.prepare_compose_override") as overlay:
            processed = regenerate_configs(paths)
        caddy.assert_not_called()
        overlay.assert_not_called()
        assert "alpha" not in processed

    @patch("boxmunge.commands.upgrade_cmd.caddy_reload")
    @patch("boxmunge.commands.upgrade_steps.compose_up")
    def test_apply_keeps_paused_offline(self, mock_up, _reload, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        _project(paths, "alpha")
        _project(paths, "beta")
        _pause(paths, "alpha")
        assert run_upgrade(paths, apply_only=True) == 0
        assert "status 503" in paths.project_caddy_site("alpha").read_text()
        assert "reverse_proxy" in paths.project_caddy_site("beta").read_text()
        started = [c.args[0].name for c in mock_up.call_args_list]
        assert started == ["beta"]


class TestDryRunWritesNothing:
    @patch("boxmunge.commands.upgrade_cmd.caddy_reload")
    @patch("boxmunge.commands.upgrade_steps.compose_up")
    def test_no_file_is_created_or_changed(self, mock_up, mock_reload, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        _project(paths, "live")
        _project(paths, "paused")
        _pause(paths, "paused")
        _project(paths, "held")
        _quarantine(paths, "held")
        _project(paths, "old", schema=1)
        before = _snapshot(paths.root)

        assert run_upgrade(paths, dry_run=True) == 0

        assert _snapshot(paths.root) == before
        mock_up.assert_not_called()
        mock_reload.assert_not_called()

    def test_reports_that_nothing_was_written(self, tmp_path: Path, capsys) -> None:
        paths = _setup(tmp_path)
        _project(paths, "live")
        run_upgrade(paths, dry_run=True)
        assert "Nothing was written" in capsys.readouterr().out

    def test_generation_failure_fails_the_dry_run(self, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        _project(paths, "live")
        before = _snapshot(paths.root)
        with patch("boxmunge.commands.upgrade_steps.generate_compose_override",
                   side_effect=RuntimeError("generator bug")):
            assert run_upgrade(paths, dry_run=True) == 1
        assert _snapshot(paths.root) == before

    def test_corrupt_manifest_fails_the_dry_run(self, tmp_path: Path) -> None:
        """apply raises on a corrupt manifest, so the pre-flight must too."""
        paths = _setup(tmp_path)
        _project(paths, "live")
        paths.project_manifest("live").write_text("- not\n- a mapping\n")
        assert run_upgrade(paths, dry_run=True) == 1

    def test_failed_migration_fails_the_dry_run(self, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        _project(paths, "old", schema=1)
        with patch("boxmunge.commands.upgrade_steps.migrate_manifest",
                   side_effect=__import__("boxmunge.migration").migration.MigrationError("x")):
            assert run_upgrade(paths, dry_run=True) == 1


class TestRegenTakesProjectLock:
    def test_locked_project_configs_are_left_alone(self, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        _project(paths, "alpha")
        _project(paths, "beta")
        lock = paths.project_lock_file("alpha")
        lock.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(lock), os.O_CREAT | os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            processed = regenerate_configs(paths)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        assert processed == ["beta"]
        assert paths.project_caddy_site("alpha").read_text() == "# live config for alpha\n"
