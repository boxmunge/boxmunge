# SPDX-License-Identifier: Apache-2.0
"""legacy-stage shows the evidence, and refuses before any step: during
probation or an interrupted upgrade, for a choice the stage does not allow,
a busy project, linked kept files, and bad arguments."""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from boxmunge.commands.legacy_stage_cmd import cmd_legacy_stage
from boxmunge.legacy_stage import get_record, legacy_stage
from boxmunge.upgrade_state import write_probation
from tests.stage_helpers import V1
from tests.test_commands.legacy_cmd_helpers import legacy_run


def test_refused_during_probation(paths, legacy, capsys) -> None:
    write_probation(paths, "0.11.0b1", "b", hours=6)
    assert legacy_run(paths, "discard") == 1
    err = capsys.readouterr().err
    assert "probation" in err and "until" in err
    assert legacy_stage(paths, "myapp") is not None
    assert (get_record(paths, "myapp") or {}).get("choice") is None


@pytest.mark.parametrize("marker", ["upgrade-inflight", "rollback-inflight"])
def test_refused_while_an_upgrade_or_rollback_is_interrupted(paths, legacy, capsys,
                                                            marker) -> None:
    (paths.root / "env-b").mkdir(parents=True, exist_ok=True)
    (paths.root / "env-b" / marker).write_text("")
    assert legacy_run(paths, "keep-staged") == 1
    assert marker in capsys.readouterr().err
    assert legacy_stage(paths, "myapp") is not None


def test_no_flag_shows_the_evidence_and_changes_nothing(paths, legacy, capsys) -> None:
    from tests.bundle_helpers import tree_snapshot
    before = tree_snapshot(legacy)
    assert legacy_run(paths, None) == 0
    out = capsys.readouterr().out
    assert "untouched" in out and "--discard" in out and "--keep-staged" in out
    assert tree_snapshot(legacy) == before
    assert get_record(paths, "myapp") is None


def test_no_flag_during_probation_still_shows_the_evidence(paths, legacy, capsys) -> None:
    write_probation(paths, "0.11.0b1", "b", hours=6)
    assert legacy_run(paths, None) == 0
    out = capsys.readouterr().out
    assert "untouched" in out and "probation" in out


def test_leftover_allows_only_discard(paths, capsys) -> None:
    from boxmunge.commands.deploy import run_deploy
    from boxmunge.project_registry import add_project
    from tests.bundle_helpers import place_bundle
    from tests.txn_helpers import docker_off
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    with docker_off():
        run_deploy("myapp", paths, ref=V1)
    (paths.project_dir("myapp") / "compose.boxmunge-staging.yml").write_text("services: {}\n")
    assert legacy_run(paths, "keep-staged") == 1
    assert "--discard" in capsys.readouterr().err
    assert legacy_run(paths, "discard") == 0
    assert legacy_stage(paths, "myapp") is None


def test_nothing_to_resolve(paths, capsys) -> None:
    assert legacy_run(paths, "discard") == 1
    assert "no release staged by boxmunge 0.10.1" in capsys.readouterr().err


def test_a_busy_project_says_so_once(paths, capsys) -> None:
    from boxmunge.commands.legacy_stage_cmd import run_legacy_stage
    from boxmunge.fileutil import project_lock
    with project_lock("myapp", paths):
        assert run_legacy_stage(paths, "myapp", None, False) == 1
    err = capsys.readouterr().err.lower()
    assert err.count("try again") == 1


@pytest.mark.parametrize("linked", ["prestage", "prestage/release"])
def test_a_linked_prestage_is_refused(paths, legacy, tmp_path, linked, capsys) -> None:
    real = legacy / ".releases" / linked
    moved = tmp_path / "moved"
    real.rename(moved)
    os.symlink(moved, real)
    assert legacy_run(paths, "discard") == 1
    assert "not a directory" in capsys.readouterr().err
    assert (legacy / "VERSION").read_text() == "v2\n"     # nothing copied in


def test_meta_json_read_through_a_link_is_refused(paths, legacy, tmp_path) -> None:
    from boxmunge.legacy_stage_ops import LegacyStageError, restore_prestage_0101
    meta = legacy / ".releases" / "prestage" / "meta.json"
    (tmp_path / "planted.json").write_text(meta.read_text())
    meta.unlink()
    os.symlink(tmp_path / "planted.json", meta)
    with pytest.raises(LegacyStageError, match="meta.json"):
        restore_prestage_0101(paths, "myapp")
    assert (legacy / "VERSION").read_text() == "v2\n"


@pytest.mark.parametrize("argv", [["myapp", "--discard", "--keep-staged"],
                                  ["myapp", "--confirm-recreated"],
                                  ["myapp", "--keep-staged", "--confirm-recreated"],
                                  [], ["myapp", "--force"]])
def test_bad_arguments_are_usage_errors(argv) -> None:
    with pytest.raises(SystemExit) as e:
        cmd_legacy_stage(argv)
    assert e.value.code == 2


@pytest.mark.parametrize("argv, expected", [
    (["myapp"], (None, False)), (["myapp", "--discard"], ("discard", False)),
    (["myapp", "--discard", "--confirm-recreated"], ("discard", True)),
    (["myapp", "--keep-staged"], ("keep-staged", False))])
def test_arguments_choose_the_action(argv, expected) -> None:
    with patch("boxmunge.commands.legacy_stage_cmd.run_legacy_stage", return_value=0) as run, \
            pytest.raises(SystemExit) as e:
        cmd_legacy_stage(argv)
    assert e.value.code == 0
    assert run.call_args.args[1:] == ("myapp", *expected)
