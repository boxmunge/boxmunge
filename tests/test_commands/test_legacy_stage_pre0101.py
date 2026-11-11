# SPDX-License-Identifier: Apache-2.0
"""A stage made before 0.10.1 (0.9.x, 0.10.0): `stage` wrote the staged
release over production's files and kept no copy of them, so the project
directory holds the staged release while production's containers still run
the one deployed before it. legacy-stage must say so, its --discard must
never start production from those files, and every start stays refused
until a deploy replaces them."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from boxmunge.compose_guard import ComposeRefused, check_kept_files, check_start
from boxmunge.legacy_stage import (
    awaiting_deploy_refusal, get_record, legacy_stage, legacy_stage_refusal,
    legacy_staging_state, refuse_if_legacy_stage,
)
from boxmunge.release import mark_live
from boxmunge.state import write_state
from tests.bundle_helpers import SAFE_COMPOSE, manifest_text
from tests.stage_helpers import V1
from tests.test_commands.legacy_cmd_helpers import legacy_run

P = "myapp"
PROD = ["compose.yml", "compose.boxmunge.yml"]
WRONG = "a 0.10.1 promote installed"


@pytest.fixture
def stage09(paths):
    """The layout 0.9.16's `stage` leaves: no .releases/, the staged files
    in the project dir, staging's compose files beside them, and the deploy
    state still naming production's release."""
    from boxmunge.project_registry import add_project
    add_project(P, paths)
    pdir = paths.project_dir(P)
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(manifest_text(P))
    (pdir / "compose.yml").write_text(SAFE_COMPOSE)
    (pdir / "VERSION").write_text("v2\n")
    (pdir / "compose.staging-base.yml").write_text("services:\n  web:\n    image: nginx\n")
    (pdir / "compose.boxmunge-staging.yml").write_text("services: {}\n")
    state = legacy_staging_state(paths, P)
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps({"active": True}))
    paths.project_deploy_state(P).parent.mkdir(parents=True, exist_ok=True)
    write_state(paths.project_deploy_state(P), {"current_ref": f"{P}-{V1}"})
    return pdir


def test_detected_as_a_stage_made_before_0101(paths, stage09) -> None:
    assert legacy_stage(paths, P).kind == "pre0101"


def test_a_0101_leftover_keeps_its_kind(paths, stage09) -> None:
    """A 0.10.1 promote whose unstage did not finish has the live.json
    every 0.10.1 deploy writes."""
    mark_live(paths, P, f"{P}-{V1}")
    assert legacy_stage(paths, P).kind == "leftover"


def test_refusal_says_what_is_on_disk(paths, stage09) -> None:
    refusal = legacy_stage_refusal(paths, P)
    assert "before 0.10.1" in refusal and "holds the staged files" in refusal
    assert WRONG not in refusal and f"boxmunge-server legacy-stage {P}" in refusal


def test_no_flag_describes_it_truthfully(paths, stage09, capsys) -> None:
    assert legacy_run(paths, None) == 0
    out = capsys.readouterr().out
    assert "before 0.10.1" in out and "holds the staged files" in out
    assert "Choices: --discard" in out and "--keep-staged" not in out
    assert WRONG not in out


def test_keep_staged_is_not_offered(paths, stage09, capsys) -> None:
    assert legacy_run(paths, "keep-staged") == 1
    assert "--discard" in capsys.readouterr().err
    assert legacy_stage(paths, P) is not None


def test_discard_never_starts_production(paths, stage09, capsys) -> None:
    with patch("boxmunge.legacy_stage_ops.finish_apply",
               side_effect=AssertionError("must not recreate from the staged files")), \
            patch("boxmunge.legacy_stage_ops._build_release",
                  side_effect=AssertionError("must not build the staged files")):
        assert legacy_run(paths, "discard") == 0
    legacy_run.up.assert_not_called()
    legacy_run.down.assert_called_once()           # staging's containers are stopped
    assert legacy_stage(paths, P) is None
    assert not (stage09 / "compose.boxmunge-staging.yml").exists()
    assert not legacy_staging_state(paths, P).exists()
    out = capsys.readouterr().out
    assert "keeps running" in out and f"prod-deploy {P}" in out
    # The record stays: it is what keeps starts refused until a deploy.
    assert get_record(paths, P)["choice"] == "discard"
    title, body = legacy_run.sent.call_args.args[1:3]
    assert P in title and f"prod-deploy {P}" in body and WRONG not in body


def test_after_discard_starts_are_refused_until_a_deploy(paths, stage09) -> None:
    with patch("boxmunge.legacy_stage_ops.finish_apply"):
        assert legacy_run(paths, "discard") == 0
    refusal = awaiting_deploy_refusal(paths, P)
    assert refusal is not None and f"prod-deploy {P}" in refusal
    with patch("boxmunge.compose_guard.notify"), pytest.raises(ComposeRefused,
                                                               match=f"prod-deploy {P}"):
        check_start(paths, P, component="resume", compose_files=PROD)
    # The upgrade checks this before it regenerates anything (REFUSED, not restarted).
    with patch("boxmunge.compose_guard.notify"), pytest.raises(ComposeRefused,
                                                               match=f"prod-deploy {P}"):
        check_kept_files(paths, P, component="upgrade")
    # Deploys are the way out: nothing refuses them for the stage any more.
    assert refuse_if_legacy_stage(paths, P) is False
    mark_live(paths, P, f"{P}-{V1}")                # what a deploy's install writes
    assert awaiting_deploy_refusal(paths, P) is None


def test_a_deploy_of_production_s_release_is_the_way_out(paths, stage09) -> None:
    from boxmunge.commands.deploy import run_deploy
    from tests.bundle_helpers import place_bundle
    from tests.txn_helpers import docker_off
    with patch("boxmunge.legacy_stage_ops.finish_apply"):
        assert legacy_run(paths, "discard") == 0
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n"})
    with docker_off():
        assert run_deploy(P, paths, ref=V1) == 0
    assert (stage09 / "VERSION").read_text() == "v1\n"
    assert awaiting_deploy_refusal(paths, P) is None


def test_rerun_after_discard_names_the_deploy(paths, stage09, capsys) -> None:
    with patch("boxmunge.legacy_stage_ops.finish_apply"):
        assert legacy_run(paths, "discard") == 0
    capsys.readouterr()
    with patch("boxmunge.legacy_stage_ops.finish_apply",
               side_effect=AssertionError("must not recreate from the staged files")):
        assert legacy_run(paths, "discard") == 0
        assert legacy_run(paths, None) == 0
    out = capsys.readouterr().out
    assert out.count(f"prod-deploy {P}") == 2
    mark_live(paths, P, f"{P}-{V1}")
    assert legacy_run(paths, None) == 0
    assert get_record(paths, P) is None              # a deploy replaced the files


def test_upgrade_dry_run_and_apply_name_the_kind(paths, stage09, capsys) -> None:
    from boxmunge.commands.upgrade_steps import _left_as_is_line
    from boxmunge.upgrade_exclusions import notify_exclusions, Exclusions
    line = _left_as_is_line(paths, P)
    assert "before 0.10.1" in line and "left as is" in line and WRONG not in line
    with patch("boxmunge.legacy_stage.notify", return_value=True) as sent:
        notify_exclusions(paths, Exclusions(legacy={P: "pre0101"}))
    title, body = sent.call_args.args[1:3]
    assert "before 0.10.1" in title + body and "holds the staged files" in body


def test_dry_run_and_apply_agree_after_discard(paths, stage09) -> None:
    from boxmunge.commands.upgrade_steps import check_upgrade
    from boxmunge.upgrade_exclusions import apply_projects
    with patch("boxmunge.legacy_stage_ops.finish_apply"):
        assert legacy_run(paths, "discard") == 0
    expected = awaiting_deploy_refusal(paths, P)
    lines = [line for line in check_upgrade(paths) if line.startswith(f"{P}:")]
    assert len(lines) == 1 and "would be refused" in lines[0] and expected in lines[0]
    with patch("boxmunge.compose_guard.notify"):
        _migration, regen, excluded = apply_projects(paths)
    assert P not in excluded.names() and P not in regen.processed
    assert expected in regen.refused[P]


def _discard_recorded_by_0115(paths, pdir, kind: str) -> None:
    """What 0.11.5 left when its --discard of a 0.9 stage crashed after
    dropping the stage (step 6) and before finish_apply: the record names
    the choice, the staging files are gone, and no deploy wrote live.json."""
    from boxmunge.legacy_stage import update_record
    for name in ("compose.staging-base.yml", "compose.boxmunge-staging.yml"):
        (pdir / name).unlink()
    legacy_staging_state(paths, P).unlink()
    update_record(paths, P, kind=kind, choice="discard")


@pytest.mark.parametrize("kind", ["leftover", "pre0101"])
def test_a_discard_an_earlier_release_recorded_never_reaches_finish_apply(
        paths, stage09, capsys, kind) -> None:
    _discard_recorded_by_0115(paths, stage09, kind)
    assert legacy_stage(paths, P) is None
    assert awaiting_deploy_refusal(paths, P) is not None
    with patch("boxmunge.legacy_stage_ops.finish_apply",
               side_effect=AssertionError("must not recreate from the staged files")):
        assert legacy_run(paths, None) == 0
        assert legacy_run(paths, "discard") == 0
    assert capsys.readouterr().out.count(f"prod-deploy {P}") == 2
    with patch("boxmunge.compose_guard.notify"), pytest.raises(ComposeRefused,
                                                               match=f"prod-deploy {P}"):
        check_start(paths, P, component="resume", compose_files=PROD)


def test_a_rerun_sends_the_alert_a_crash_before_step_8_lost(paths, stage09) -> None:
    _discard_recorded_by_0115(paths, stage09, "pre0101")
    with patch("boxmunge.legacy_stage_ops.finish_apply"):
        assert legacy_run(paths, None) == 0
        assert legacy_run.sent.call_count == 1
        assert f"prod-deploy {P}" in legacy_run.sent.call_args.args[2]
        assert get_record(paths, P)["last_alert"]
        assert legacy_run(paths, None) == 0
        legacy_run.sent.assert_not_called()           # sent once, not on every rerun


def test_check_all_names_the_deploy_after_discard(paths, stage09, capsys) -> None:
    from boxmunge.commands.check import _check_one
    with patch("boxmunge.legacy_stage_ops.finish_apply"):
        assert legacy_run(paths, "discard") == 0
    assert _check_one(P, paths, True) == 1
    assert f"prod-deploy {P}" in capsys.readouterr().out
