"""Planted links where the slot and its debris live (Review Focus 5).

The slot, staged.building and *.discarded are boxmunge's own directories in
deploy-writable .releases/. A link (or a file) there was planted: stage and
unstage refuse before any compose call, follow nothing, remove nothing,
name the path and say to remove it by hand. Nothing ends in a traceback.
"""
from __future__ import annotations

import os
import shutil
from unittest.mock import patch

import pytest

from boxmunge.commands.stage_cmd import run_stage
from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.staged_release import load_slot, slot_dir
from tests.bundle_helpers import place_bundle, tree_snapshot
from tests.stage_helpers import V3, prod_and_stage, staging_docker_off


def _plant(paths, tmp_path, name: str):
    """Replace (or create) .releases/<name> with a link to a real directory."""
    rel = paths.project_releases("myapp")
    target = tmp_path / f"elsewhere-{name}"
    path = rel / name
    if path.is_dir():
        shutil.copytree(path, target)
        shutil.rmtree(path)
    else:
        target.mkdir()
        (target / "keep").write_text("not boxmunge's")
    os.symlink(target, path)
    return path, target


PLANTED = pytest.mark.parametrize("name", ["staged", "staged.building", "staged.discarded"])


@PLANTED
def test_unstage_refuses_a_planted_link(paths, tmp_path, capsys, name) -> None:
    prod_and_stage(paths)
    path, target = _plant(paths, tmp_path, name)
    before = tree_snapshot(target)
    with staging_docker_off() as docker:
        assert run_unstage("myapp", paths) == 1
    docker["down"].assert_not_called()
    err = capsys.readouterr().err
    assert str(path) in err and "remove it by hand" in err
    assert os.path.islink(path) and tree_snapshot(target) == before
    assert paths.project_staging_caddy_site("myapp").exists()  # nothing else removed


@PLANTED
def test_restage_refuses_a_planted_link(paths, tmp_path, capsys, name) -> None:
    prod_and_stage(paths)
    path, target = _plant(paths, tmp_path, name)
    before = tree_snapshot(target)
    place_bundle(paths, timestamp=V3, files={"VERSION": "v3\n"})
    with staging_docker_off() as docker:
        assert run_stage("myapp", paths, ref=V3) == 1
    docker["down_retire"].assert_not_called()
    docker["up"].assert_not_called()
    err = capsys.readouterr().err
    assert str(path) in err and "remove it by hand" in err
    assert os.path.islink(path) and tree_snapshot(target) == before
    names = sorted(p.name for p in paths.project_releases("myapp").iterdir())
    assert "staged.building" not in names or name == "staged.building"


def test_a_planted_file_in_place_of_the_slot_is_refused(paths, capsys) -> None:
    prod_and_stage(paths)
    slot = slot_dir(paths, "myapp")
    shutil.rmtree(slot)
    slot.write_text("planted")
    with staging_docker_off() as docker:
        assert run_unstage("myapp", paths) == 1
    docker["down"].assert_not_called()
    assert "remove it by hand" in capsys.readouterr().err and slot.read_text() == "planted"


def test_a_failed_swap_tears_the_stage_down_and_says_so(paths, capsys) -> None:
    prod_and_stage(paths)
    place_bundle(paths, timestamp=V3)
    with staging_docker_off(), \
            patch("boxmunge.commands.stage_cmd.swap_in", side_effect=OSError("EIO")):
        assert run_stage("myapp", paths, ref=V3) == 1
    captured = capsys.readouterr()
    assert "EIO" in captured.err and "cleaned up" in captured.out
    assert load_slot(paths, "myapp") is None


@pytest.mark.parametrize("step", ["drop_slot", "remove_site"])
def test_a_failed_teardown_step_is_reported_not_raised(paths, capsys, step) -> None:
    prod_and_stage(paths)
    with staging_docker_off(), \
            patch(f"boxmunge.commands.unstage_cmd.{step}", side_effect=OSError("EROFS")):
        assert run_unstage("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "EROFS" in err and "run 'unstage myapp' again" in err


def test_unstage_over_an_unreadable_record_points_at_recover(paths, capsys) -> None:
    prod_and_stage(paths)
    (slot_dir(paths, "myapp") / "meta.json").write_text("{broken")
    with staging_docker_off():
        assert run_unstage("myapp", paths) == 0
    assert "boxmunge recover myapp" in capsys.readouterr().out


def test_retire_refuses_a_planted_slot_before_any_compose_call(paths, tmp_path) -> None:
    from boxmunge.stage_slot import retire_previous_staging
    prod_and_stage(paths)
    path, _ = _plant(paths, tmp_path, "staged")
    with staging_docker_off() as docker, pytest.raises(OSError, match="remove it by hand"):
        retire_previous_staging(paths, "myapp")
    docker["down_retire"].assert_not_called()
    assert os.path.islink(path)


def test_prod_deploy_beside_a_planted_slot_refuses_without_a_traceback(
        paths, tmp_path, capsys) -> None:
    from boxmunge.commands.deploy import run_deploy
    prod_and_stage(paths)
    _plant(paths, tmp_path, "staged")
    place_bundle(paths, timestamp=V3)
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=V3) == 1
    assert "remove it by hand" in capsys.readouterr().err
