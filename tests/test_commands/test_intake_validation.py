"""C-01 / A-02: a bundle is validated before it touches the live project tree.

A rejected bundle (hostile compose, bad manifest, wrong identity) must leave
the live tree byte-for-byte untouched, so no later root timer can start it.
"""
from __future__ import annotations

from unittest.mock import patch

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.project_registry import add_project

from tests.bundle_helpers import (
    HOSTILE_COMPOSE, place_bundle, tree_snapshot,
)


def _deploy_working(paths) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp="2026-10-13T090000000000",
                 files={"VERSION": "v1-good\n"})
    with patch("boxmunge.commands.deploy.compose_up"), \
            patch("boxmunge.commands.deploy.caddy_reload"):
        assert run_deploy("myapp", paths) == 0


class TestDeployRejectsBeforeTouchingLiveTree:
    def test_hostile_compose_leaves_live_tree_unchanged(self, paths) -> None:
        _deploy_working(paths)
        project_dir = paths.project_dir("myapp")
        before = tree_snapshot(project_dir)

        bundle = place_bundle(paths, timestamp="2026-10-13T100000000000",
                              files={"compose.yml": HOSTILE_COMPOSE,
                                     "VERSION": "v2-bad\n"})
        with patch("boxmunge.commands.deploy.compose_up") as up, \
                patch("boxmunge.commands.deploy.caddy_reload"):
            rc = run_deploy("myapp", paths)

        assert rc == 3
        up.assert_not_called()
        assert tree_snapshot(project_dir) == before
        assert "privileged" not in (project_dir / "compose.yml").read_text()
        # The rejected bundle is not consumed: it stays visible in the inbox.
        assert bundle.exists()

    def test_invalid_manifest_leaves_live_tree_unchanged(self, paths) -> None:
        _deploy_working(paths)
        project_dir = paths.project_dir("myapp")
        before = tree_snapshot(project_dir)

        place_bundle(paths, timestamp="2026-10-13T100000000000",
                     files={"manifest.yml": "project: myapp\n"})
        with patch("boxmunge.commands.deploy.compose_up") as up:
            rc = run_deploy("myapp", paths)

        assert rc == 1
        up.assert_not_called()
        assert tree_snapshot(project_dir) == before

    def test_rejected_first_deploy_leaves_no_project_tree(self, paths) -> None:
        add_project("myapp", paths)
        place_bundle(paths, files={"compose.yml": HOSTILE_COMPOSE})
        with patch("boxmunge.commands.deploy.compose_up") as up:
            rc = run_deploy("myapp", paths)
        assert rc == 3
        up.assert_not_called()
        assert not paths.project_dir("myapp").exists()

    def test_dry_run_leaves_live_tree_unchanged(self, paths) -> None:
        _deploy_working(paths)
        project_dir = paths.project_dir("myapp")
        before = tree_snapshot(project_dir)
        bundle = place_bundle(paths, timestamp="2026-10-13T100000000000",
                              files={"VERSION": "v2\n"})
        assert run_deploy("myapp", paths, dry_run=True) == 0
        assert tree_snapshot(project_dir) == before
        assert bundle.exists()


class TestStageRejectsBeforeTouchingLiveTree:
    def test_hostile_compose_leaves_prod_tree_unchanged(self, paths) -> None:
        _deploy_working(paths)
        project_dir = paths.project_dir("myapp")
        before = tree_snapshot(project_dir)

        place_bundle(paths, timestamp="2026-10-13T100000000000",
                     files={"compose.yml": HOSTILE_COMPOSE})
        with patch("boxmunge.commands.stage_cmd.compose_up") as up, \
                patch("boxmunge.commands.stage_cmd.caddy_reload"):
            rc = run_stage("myapp", paths)

        assert rc == 3
        up.assert_not_called()
        assert tree_snapshot(project_dir) == before
        assert not paths.project_staging_caddy_site("myapp").exists()


class TestInstallFailureAdvice:
    def _fail_install(self, paths):
        with patch("boxmunge.commands.deploy.install_release",
                   side_effect=OSError("disk full")), \
                patch("boxmunge.commands.deploy.compose_up") as up:
            rc = run_deploy("myapp", paths)
        up.assert_not_called()
        return rc

    def test_first_deploy_does_not_advise_rollback(self, paths, capsys) -> None:
        add_project("myapp", paths)
        place_bundle(paths)
        assert self._fail_install(paths) == 1
        err = capsys.readouterr().err
        assert "disk full" in err
        assert "rollback" not in err

    def test_upgrade_advises_rollback(self, paths, capsys) -> None:
        _deploy_working(paths)
        place_bundle(paths, timestamp="2026-10-13T100000000000")
        assert self._fail_install(paths) == 1
        assert "rollback myapp" in capsys.readouterr().err
