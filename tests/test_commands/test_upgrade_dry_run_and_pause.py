# SPDX-License-Identifier: Apache-2.0
"""C-05: an upgrade keeps paused projects on the maintenance page, and
`upgrade --dry-run` writes nothing at all."""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge.commands.upgrade_cmd import run_upgrade
from boxmunge.commands.upgrade_steps import UpgradeGateError, check_upgrade
from boxmunge.compose import ComposeError
from boxmunge.docker_run import DockerError
from boxmunge.upgrade_exclusions import apply_projects
from boxmunge.manifest import CURRENT_SCHEMA_VERSION
from boxmunge.pause import render_maintenance_caddy_config, write_paused_state
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError
from boxmunge.version import write_installed_version
from tests.deploy_helpers import mark_deployed


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
    mark_deployed(paths, name)


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
        apply_projects(paths)[1]
        content = paths.project_caddy_site("alpha").read_text()
        assert "status 503" in content
        assert "reverse_proxy" not in content

    def test_regen_keeps_paused_routing_but_regenerates_its_overlay(self, tmp_path: Path) -> None:
        """Resume starts this release's overlay, so the upgrade writes it and
        records its bind sources, as for a running project (see
        tests/integration/test_upgrade_blocked_lift.py)."""
        paths = _setup(tmp_path)
        _project(paths, "alpha")
        _pause(paths, "alpha")
        with patch("boxmunge.commands.upgrade_steps.prepare_caddy_config") as caddy, \
             patch("boxmunge.commands.upgrade_offline.prepare_compose_override") as overlay, \
             patch("boxmunge.commands.upgrade_offline.check_start") as check:
            processed = apply_projects(paths)[1].processed
        caddy.assert_not_called()
        overlay.assert_called_once()
        assert check.call_args.kwargs["record"] is True
        assert "alpha" in processed

    @patch("boxmunge.commands.upgrade_cmd.caddy_reload")
    @patch("boxmunge.compose_guard.compose_up")
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
    @patch("boxmunge.compose_guard.compose_up")
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
        with patch("boxmunge.commands.upgrade_offline.render_compose_override",
                   side_effect=RuntimeError("generator bug")):
            assert run_upgrade(paths, dry_run=True) == 1
        assert _snapshot(paths.root) == before

    def test_an_unreadable_users_record_fails_the_dry_run(self, tmp_path: Path) -> None:
        """The dry run renders the overlay the apply writes, users record
        included: the apply would fail on this one after the swap."""
        paths = _setup(tmp_path)
        _project(paths, "live")
        paths.project_users_record("live").write_text("not json\n")
        with pytest.raises(ComposeError, match="cannot read the users record"):
            check_upgrade(paths)
        assert run_upgrade(paths, dry_run=True) == 1

    def test_a_paused_project_whose_overlay_fails_is_reported_not_fatal(
            self, tmp_path: Path) -> None:
        """The apply regenerates a paused project's overlay too, and refuses
        (not fails on) one it cannot."""
        paths = _setup(tmp_path)
        _project(paths, "paused")
        _pause(paths, "paused")
        assert check_upgrade(paths) == [
            "paused: paused; keeps its maintenance page, overlay renders OK"]
        paths.project_users_record("paused").write_text("not json\n")
        [line] = check_upgrade(paths)
        assert line.startswith("paused: paused; keeps its maintenance page; would be refused")
        assert "cannot read the users record" in line
        assert run_upgrade(paths, dry_run=True) == 0

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


class TestOfflineOverlayRefused:
    """A paused or quarantined project whose overlay cannot be regenerated
    is refused like a compose refusal: alerted, left on its previous overlay
    and bind record (which still agree), and the upgrade goes on."""

    @patch("boxmunge.commands.upgrade_cmd.caddy_reload")
    @patch("boxmunge.compose_guard.compose_up")
    def test_refused_and_alerted_keeping_its_previous_files(
            self, mock_up, _reload, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        _project(paths, "alpha")
        _project(paths, "beta")
        _quarantine(paths, "alpha")
        paths.project_compose_override("alpha").write_text("# previous overlay\n")
        paths.project_users_record("alpha").write_text('{"web": "not an entry"}\n')
        kept = {f: f.read_bytes() for f in (paths.project_compose_override("alpha"),
                                            paths.project_bind_record("alpha"))}
        with patch("boxmunge.notify.notify") as alert:
            assert run_upgrade(paths, apply_only=True) == 0
        assert {f: f.read_bytes() for f in kept} == kept
        [(title, body)] = [c.args[1:3] for c in alert.call_args_list
                           if "refused" in c.args[1]]
        assert "- alpha: its compose overlay could not be regenerated" in body
        assert "entry 'web' is not {user, source, image_user}" in body
        assert [c.args[0].name for c in mock_up.call_args_list] == ["beta"]
        assert "status 503" in paths.project_caddy_site("alpha").read_text()

    def test_a_failure_after_the_write_puts_the_previous_files_back(
            self, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        _project(paths, "alpha")
        _project(paths, "beta")
        _pause(paths, "alpha")
        _pause(paths, "beta")
        paths.project_compose_override("alpha").write_text("# previous overlay\n")
        record = paths.project_bind_record("alpha").read_bytes()
        assert not paths.project_compose_override("beta").exists()

        def written_then_failed(paths, manifest, component):
            name = manifest["project"]
            paths.project_compose_override(name).write_text("# half written\n")
            paths.project_bind_record(name).write_text("{}\n")
            raise DockerError("docker image rm timed out")

        with patch("boxmunge.commands.upgrade_offline.prepare_compose_override",
                   written_then_failed):
            regen = apply_projects(paths)[1]
        assert set(regen.refused) == {"alpha", "beta"}
        assert "docker image rm timed out" in regen.refused["alpha"]
        assert paths.project_compose_override("alpha").read_text() == "# previous overlay\n"
        assert paths.project_bind_record("alpha").read_bytes() == record
        assert not paths.project_compose_override("beta").exists()


    @pytest.mark.parametrize("linked", ["overlay", "record"])
    def test_a_linked_overlay_or_record_is_refused_and_never_copied(
            self, tmp_path: Path, linked: str) -> None:
        """Putting the previous files back must not copy whatever a planted
        link names (a root-only file) into the project directory, deploy-owned:
        a link is refused before anything is regenerated."""
        paths = _setup(tmp_path)
        _project(paths, "alpha")
        _quarantine(paths, "alpha")
        secret = tmp_path / "root-only"
        secret.write_text("SECRET\n")
        target = (paths.project_compose_override("alpha") if linked == "overlay"
                  else paths.project_bind_record("alpha"))
        target.unlink(missing_ok=True)
        target.symlink_to(secret)
        paths.project_users_record("alpha").write_text('{"web": "not an entry"}\n')
        [line] = check_upgrade(paths)
        assert "would be refused" in line and "is a symlink" in line
        regen = apply_projects(paths)[1]
        assert "is a symlink" in regen.refused["alpha"]
        assert "nothing was changed" in regen.refused["alpha"]
        assert target.is_symlink() and secret.read_text() == "SECRET\n"
        assert not any("SECRET" in f.read_text() for f in paths.project_dir("alpha").rglob("*")
                       if f.is_file() and not f.is_symlink())

    def test_a_failure_to_record_is_refused_and_puts_the_previous_files_back(
            self, tmp_path: Path) -> None:
        """Any failure of the record step, not only a start-check refusal
        (here an unreadable state file), refuses the project, not the upgrade."""
        paths = _setup(tmp_path)
        _project(paths, "alpha")
        _pause(paths, "alpha")
        paths.project_compose_override("alpha").write_text("# previous overlay\n")
        record = paths.project_bind_record("alpha").read_bytes()
        with patch("boxmunge.commands.upgrade_offline.check_start",
                   side_effect=StateError("Cannot read state file other.users.json")):
            regen = apply_projects(paths)[1]
        assert regen.refused["alpha"].startswith("its bind sources could not be recorded")
        assert "Cannot read state file" in regen.refused["alpha"]
        assert paths.project_compose_override("alpha").read_text() == "# previous overlay\n"
        assert paths.project_bind_record("alpha").read_bytes() == record

    def test_previous_files_that_cannot_be_put_back_fail_the_upgrade(
            self, tmp_path: Path) -> None:
        """Then the overlay and record may disagree: that is not left behind
        as a refusal."""
        paths = _setup(tmp_path)
        _project(paths, "alpha")
        _pause(paths, "alpha")
        paths.project_compose_override("alpha").write_text("# previous overlay\n")

        def written_then_failed(paths, manifest, component):
            paths.project_compose_override("alpha").write_text("# half written\n")
            raise DockerError("docker image rm timed out")

        with patch("boxmunge.commands.upgrade_offline.prepare_compose_override",
                   written_then_failed), \
             patch("boxmunge.commands.upgrade_offline.atomic_write_bytes",
                   side_effect=OSError(28, "No space left on device")), \
             pytest.raises(UpgradeGateError, match="could not be put back.*No space left"):
            apply_projects(paths)

    def test_nothing_changed_means_nothing_to_put_back(self, tmp_path: Path) -> None:
        """A regeneration that fails before writing leaves nothing to restore,
        so a failing write could not matter: the project is just refused."""
        paths = _setup(tmp_path)
        _project(paths, "alpha")
        _pause(paths, "alpha")
        paths.project_users_record("alpha").write_text('{"web": "not an entry"}\n')
        with patch("boxmunge.commands.upgrade_offline.atomic_write_bytes",
                   side_effect=OSError(28, "No space left on device")):
            regen = apply_projects(paths)[1]
        assert "could not be regenerated" in regen.refused["alpha"]


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
            processed = apply_projects(paths)[1].processed
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        assert processed == ["beta"]
        assert paths.project_caddy_site("alpha").read_text() == "# live config for alpha\n"


class TestPausedPreRuleContainers:
    """Logic review 01: a paused project whose stopped containers mount the
    project directory read-write (0.10.x accepted `.:/app`). The upgrade
    starts none of them, so it records the new overlay; `resume`, which the
    upgrade names, recreates them from the checked files."""

    def test_the_upgrade_records_it_and_resume_brings_it_back(
            self, tmp_path: Path, monkeypatch) -> None:
        from boxmunge.commands.resume_cmd import resume_locked
        from boxmunge.pause import is_paused, mark_pause_complete
        paths = _setup(tmp_path)
        _project(paths, "alpha")
        _pause(paths, "alpha")
        mark_pause_complete("alpha", paths)
        pdir = str(paths.project_dir("alpha"))
        monkeypatch.setattr("boxmunge.docker_containers.container_bind_sources",
                            lambda project: [(pdir, True)])
        regen = apply_projects(paths)[1]
        assert regen.refused == {} and "alpha" in regen.processed
        assert paths.project_compose_override("alpha").exists()
        with patch("boxmunge.compose_guard.compose_up") as up, \
                patch("boxmunge.commands.resume_cmd.caddy_reload"), \
                patch("boxmunge.commands.resume_cmd.run_smoke", return_value=(True, "ok")):
            assert resume_locked("alpha", paths, skip_security_checks=True) == (0, None)
        assert up.call_args.kwargs["force_recreate"] is True
        assert not is_paused("alpha", paths)

    def test_a_refused_paused_project_is_told_to_resume(self, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        _project(paths, "alpha")
        _pause(paths, "alpha")
        paths.project_users_record("alpha").write_text('{"web": "not an entry"}\n')
        with patch("boxmunge.commands.upgrade_steps.log_error") as logged:
            assert "alpha" in apply_projects(paths)[1].refused
        message = logged.call_args.args[1]
        # A deploy is refused while it is paused: one is named only after the
        # resume that hands the pause to it.
        assert "resume alpha" in message
        assert message.count("redeploy") == message.count(
            "`boxmunge resume alpha --no-start`, then `boxmunge prod-deploy alpha --redeploy`")
