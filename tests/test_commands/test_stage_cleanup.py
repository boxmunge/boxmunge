"""C-13: a failed stage cleans up after itself, and unstage cleans up
whatever a stage left behind, recorded as active or not.

Before, stage wrote the staging Caddy site and compose files and could start
containers before recording {"active": true}; any later failure returned 1
with all of it left behind (and prod's files replaced), and unstage refused
because no staging was "active".
"""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

import pytest

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.docker import DockerError
from boxmunge.project_registry import add_project
from boxmunge.state import read_state

from tests.bundle_helpers import place_bundle, tree_snapshot

V1 = "2026-10-13T090000000000"
V2 = "2026-10-13T100000000000"


@contextmanager
def _docker(stage_up=None):
    with patch("boxmunge.commands.deploy.compose_up"), \
            patch("boxmunge.commands.deploy.caddy_reload"), \
            patch("boxmunge.commands.stage_cmd.compose_up", side_effect=stage_up), \
            patch("boxmunge.commands.stage_cmd.caddy_reload"), \
            patch("boxmunge.commands.unstage_cmd.compose_down") as down, \
            patch("boxmunge.commands.unstage_cmd.caddy_reload"):
        yield down


@pytest.fixture
def prod(paths):
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n"})
    with _docker():
        assert run_deploy("myapp", paths) == 0
    return paths.project_dir("myapp")


def _staging_artefacts(paths):
    pdir = paths.project_dir("myapp")
    return [p for p in (
        paths.project_staging_caddy_site("myapp"),
        paths.project_staging_compose_override("myapp"),
        pdir / "compose.staging-base.yml",
        pdir / ".releases" / "prestage",
    ) if p.exists()]


class TestFailedStageCleansUp:
    def test_compose_failure_restores_prod_and_removes_artefacts(
        self, paths, prod, capsys,
    ) -> None:
        before = tree_snapshot(prod)
        place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
        with _docker(stage_up=DockerError("boom")) as down:
            assert run_stage("myapp", paths) == 1
        down.assert_called_once()
        assert down.call_args.kwargs["project_name"] == "myapp-staging"
        assert _staging_artefacts(paths) == []
        assert tree_snapshot(prod) == before
        assert read_state(paths.project_staging_state("myapp")).get("active") is not True
        assert "cleaned up" in capsys.readouterr().out

    def test_data_snapshot_failure_cleans_up(self, paths, prod) -> None:
        before = tree_snapshot(prod)
        manifest = (prod / "manifest.yml").read_text() + "staging:\n  copy_data: true\n"
        place_bundle(paths, timestamp=V2, files={"manifest.yml": manifest})
        with _docker(), patch("boxmunge.staging_data.snapshot_prod_data",
                              side_effect=RuntimeError("disk full")):
            assert run_stage("myapp", paths) == 1
        assert _staging_artefacts(paths) == []
        assert tree_snapshot(prod) == before

    def test_failed_first_stage_leaves_project_undeployed(self, paths) -> None:
        add_project("myapp", paths)
        place_bundle(paths, timestamp=V1)
        with _docker(stage_up=DockerError("boom")):
            assert run_stage("myapp", paths) == 1
        assert not (paths.project_dir("myapp") / "manifest.yml").exists()
        assert _staging_artefacts(paths) == []


class TestUnstage:
    def test_unstage_restores_the_production_release(self, paths, prod) -> None:
        before = tree_snapshot(prod)
        place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
        with _docker():
            assert run_stage("myapp", paths) == 0
            assert (prod / "VERSION").read_text() == "v2\n"
            assert run_unstage("myapp", paths) == 0
        assert tree_snapshot(prod) == before
        assert _staging_artefacts(paths) == []

    def test_unstage_cleans_up_without_active_state(self, paths, prod) -> None:
        """A stage that died before recording state still leaves artefacts
        that unstage must be able to remove."""
        site = paths.project_staging_caddy_site("myapp")
        site.write_text("staging.myapp.example.com {}\n")
        override = paths.project_staging_compose_override("myapp")
        override.write_text("services: {}\n")
        with _docker() as down:
            assert run_unstage("myapp", paths) == 0
        down.assert_called_once()
        assert _staging_artefacts(paths) == []

    def test_unstage_with_nothing_staged_is_an_error(self, paths, prod, capsys) -> None:
        with _docker():
            assert run_unstage("myapp", paths) == 1
        assert "No staging" in capsys.readouterr().err

    def test_unstage_is_repeatable(self, paths, prod) -> None:
        place_bundle(paths, timestamp=V2)
        with _docker():
            assert run_stage("myapp", paths) == 0
            assert run_unstage("myapp", paths) == 0
            assert run_unstage("myapp", paths) == 1


class TestPrestageIsAtomic:
    def test_failure_writing_metadata_leaves_no_half_kept_release(self, paths, prod) -> None:
        """A kept production release only appears once its metadata exists,
        so unstage/promote never find a release they cannot label."""
        from boxmunge import release
        place_bundle(paths, timestamp=V2)
        with patch("boxmunge.release.atomic_write_text", side_effect=OSError("disk full")), \
                _docker():
            assert run_stage("myapp", paths) == 1
        assert not release.has_prestage(paths, "myapp")
        assert (prod / "VERSION").read_text() == "v1\n"
