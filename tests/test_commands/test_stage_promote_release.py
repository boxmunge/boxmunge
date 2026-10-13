"""stage/promote keep the production release so rollback stays truthful.

stage installs the staged release into the shared project dir; the
production release it displaced is kept until promote (it becomes the
previous release, the rollback target) or unstage.
"""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.promote_cmd import run_promote
from boxmunge.commands.rollback import find_rollback_target, run_rollback
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.project_registry import add_project
from boxmunge.state import read_state

from tests.bundle_helpers import place_bundle

V1 = "2026-10-13T090000000000"
V2 = "2026-10-13T100000000000"


@contextmanager
def _docker():
    with patch("boxmunge.commands.deploy.compose_up"), \
            patch("boxmunge.commands.deploy.caddy_reload"), \
            patch("boxmunge.commands.stage_cmd.compose_up"), \
            patch("boxmunge.commands.stage_cmd.caddy_reload"), \
            patch("boxmunge.commands.unstage_cmd.compose_down"), \
            patch("boxmunge.commands.unstage_cmd.caddy_reload"):
        yield


def _prod_v1_staged_v2(paths):
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n"})
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    with _docker():
        assert run_deploy("myapp", paths, ref=V1) == 0
        assert run_stage("myapp", paths, ref=V2) == 0
    return paths.project_dir("myapp")


def test_stage_records_the_staged_bundle_ref(paths) -> None:
    _prod_v1_staged_v2(paths)
    assert read_state(paths.project_staging_state("myapp"))["ref"] == f"myapp-{V2}"


def test_prod_deploy_refused_while_a_release_is_staged(paths, capsys) -> None:
    _prod_v1_staged_v2(paths)
    place_bundle(paths, timestamp="2026-10-13T110000000000")
    with _docker():
        assert run_deploy("myapp", paths) == 1
    assert "promote myapp" in capsys.readouterr().err


def test_promote_makes_the_production_release_the_rollback_target(paths) -> None:
    pdir = _prod_v1_staged_v2(paths)
    with _docker():
        assert run_promote("myapp", paths) == 0
    assert (pdir / "VERSION").read_text() == "v2\n"
    state = read_state(paths.project_deploy_state("myapp"))
    assert state["current_ref"] == f"myapp-{V2}"
    assert find_rollback_target(paths, "myapp").ref == f"myapp-{V1}"

    with _docker():
        assert run_rollback("myapp", paths, yes=True) == 0
    assert (pdir / "VERSION").read_text() == "v1\n"


def test_promote_never_deploys_a_newer_inbox_bundle(paths) -> None:
    pdir = _prod_v1_staged_v2(paths)
    place_bundle(paths, timestamp="2026-10-13T110000000000",
                 files={"VERSION": "v3-unstaged\n"})
    with _docker():
        assert run_promote("myapp", paths) == 0
    assert (pdir / "VERSION").read_text() == "v2\n"


def test_first_stage_then_promote_has_no_rollback_target(paths, capsys) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    with _docker():
        assert run_stage("myapp", paths) == 0
        assert run_promote("myapp", paths) == 0
        assert run_rollback("myapp", paths, yes=True) == 1
    assert "no previous release" in capsys.readouterr().err
