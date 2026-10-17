"""C-13: a failed stage cleans up after itself, and unstage cleans up
whatever a stage left behind, completed or not.

A stage builds its release in the slot (.releases/staged); a failure after
the swap tears the whole stage down (D16), and production's tree is never
written, so there is nothing of production's to put back.
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
from boxmunge.staged_release import building_dir, slot_dir

from tests.bundle_helpers import place_bundle, tree_snapshot

V1 = "2026-10-13T090000000000"
V2 = "2026-10-13T100000000000"


@contextmanager
def _docker(stage_up=None):
    def up(*_args, project_name, **_kwargs):
        # `stage_up` fails the staging start; production's still succeeds.
        if stage_up is not None and project_name.endswith("-staging"):
            raise stage_up

    with patch("boxmunge.compose_guard.compose_up", side_effect=up), \
            patch("boxmunge.commands.deploy.caddy_reload"), \
            patch("boxmunge.staging_bringup.caddy_reload"), \
            patch("boxmunge.stage_slot.compose_down"), \
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
    return [p for p in (
        paths.project_staging_caddy_site("myapp"),
        paths.project_bind_record("myapp", staging=True),
        slot_dir(paths, "myapp"),
        building_dir(paths, "myapp"),
    ) if p.exists()]


class TestFailedStageCleansUp:
    def test_compose_failure_removes_every_artefact(self, paths, prod, capsys) -> None:
        before = tree_snapshot(prod)
        place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
        with _docker(stage_up=DockerError("boom")) as down:
            assert run_stage("myapp", paths) == 1
        down.assert_called_once()
        assert down.call_args.kwargs["project_name"] == "myapp-staging"
        assert _staging_artefacts(paths) == []
        assert tree_snapshot(prod) == before
        assert "cleaned up" in capsys.readouterr().out

    def test_data_copy_failure_cleans_up(self, paths, prod) -> None:
        before = tree_snapshot(prod)
        manifest = (prod / "manifest.yml").read_text() + "staging:\n  copy_data: true\n"
        place_bundle(paths, timestamp=V2, files={"manifest.yml": manifest})
        with _docker() as down, \
                patch("boxmunge.staging_bringup.check_staging_storage"), \
                patch("boxmunge.staging_bringup.prepare_destinations"), \
                patch("boxmunge.staging_bringup.copy_production_data",
                      side_effect=DockerError("disk full")) as copy:
            assert run_stage("myapp", paths) == 1
        copy.assert_called_once()
        down.assert_called_once()  # the created, never started staging is removed
        assert _staging_artefacts(paths) == []
        assert tree_snapshot(prod) == before

    def test_failed_first_stage_leaves_project_undeployed(self, paths) -> None:
        add_project("myapp", paths)
        place_bundle(paths, timestamp=V1)
        with _docker(stage_up=DockerError("boom")):
            assert run_stage("myapp", paths) == 1
        assert not (paths.project_dir("myapp") / "manifest.yml").exists()
        assert _staging_artefacts(paths) == []

    def test_failure_writing_the_record_leaves_no_slot(self, paths, prod) -> None:
        """A slot only appears complete, with its record: a failed write
        before the swap leaves nothing for unstage or promote to find."""
        before = tree_snapshot(prod)
        place_bundle(paths, timestamp=V2)
        with patch("boxmunge.staged_release.atomic_write_text",
                   side_effect=OSError("disk full")), _docker():
            assert run_stage("myapp", paths) == 1
        assert _staging_artefacts(paths) == []
        assert tree_snapshot(prod) == before


class TestUnstage:
    def test_unstage_leaves_production_as_it_was(self, paths, prod) -> None:
        before = tree_snapshot(prod)
        place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
        with _docker():
            assert run_stage("myapp", paths) == 0
            assert (prod / "VERSION").read_text() == "v1\n"
            assert run_unstage("myapp", paths) == 0
        assert tree_snapshot(prod) == before
        assert _staging_artefacts(paths) == []

    def test_unstage_cleans_up_a_stage_that_never_finished(self, paths, prod) -> None:
        """A stage that died after the swap leaves a `starting` slot and a
        site that unstage must be able to remove."""
        place_bundle(paths, timestamp=V2)
        with _docker(), patch("boxmunge.commands.stage_cmd.teardown_staging_locked",
                              return_value=True), \
                patch("boxmunge.staging_bringup.compose_up_checked",
                      side_effect=DockerError("killed")):
            assert run_stage("myapp", paths) == 1
        assert slot_dir(paths, "myapp").is_dir()
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
