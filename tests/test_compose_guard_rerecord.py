"""An upgrade renews a project's bind record from the configs it regenerates
(D-02). It must not bless a control file a container rewrote since the
deploy, even one the validator accepts: the files boxmunge did not just
write must still hash to the record first. Only a redeploy re-blesses."""
from __future__ import annotations

import json

import pytest
import yaml

from boxmunge.compose_guard import ComposeRefused, check_start
from tests import test_compose_guard as guard
from tests.test_compose_guard import NAME, _deploy, _restart

box = guard.box  # the fixture, shared with the start-check tests


def _upgrade_record(paths) -> None:
    check_start(paths, NAME, component="upgrade", compose_files=["compose.yml"],
                record=True, regenerated=True)


def _record(paths) -> dict:
    return json.loads(paths.project_bind_record(NAME).read_text())


def _profile_off(project_dir) -> None:
    manifest = yaml.safe_load((project_dir / "manifest.yml").read_text())
    manifest["security"] = {"profile": "off", "reason": "attacker-supplied"}
    (project_dir / "manifest.yml").write_text(yaml.safe_dump(manifest))


def test_an_upgrade_does_not_bless_a_rewritten_control_file(box) -> None:
    paths, project_dir, *_ = box
    _deploy(paths)
    before = _record(paths)
    _profile_off(project_dir)
    with pytest.raises(ComposeRefused, match="control file manifest.yml changed") as e:
        _upgrade_record(paths)
    assert "prod-deploy shop --redeploy" in str(e.value)
    assert _record(paths) == before
    with pytest.raises(ComposeRefused, match="control file manifest.yml changed"):
        _restart(paths)


def test_an_upgrade_renews_the_record_for_the_overlay_it_regenerated(box) -> None:
    paths, project_dir, *_ = box
    (project_dir / "compose.boxmunge.yml").write_text("services: {}\n")
    _deploy(paths)
    (project_dir / "compose.boxmunge.yml").write_text("services: {web: {init: true}}\n")
    _upgrade_record(paths)
    _restart(paths)


def test_an_upgrade_records_a_file_this_boxmunge_newly_reads(box) -> None:
    """A file the record does not track yet is taken as it is: the upgrade
    is how a newer boxmunge starts tracking one."""
    paths, project_dir, *_ = box
    _deploy(paths)
    doc = _record(paths)
    del doc["control"]["manifest.yml"]
    paths.project_bind_record(NAME).write_text(json.dumps(doc))
    _upgrade_record(paths)
    assert _record(paths)["control"]["manifest.yml"]


def test_an_upgrade_records_a_project_never_recorded(box) -> None:
    paths, *_ = box
    _upgrade_record(paths)
    _restart(paths)


def test_regenerated_means_a_record(box) -> None:
    paths, *_ = box
    with pytest.raises(ValueError, match="record"):
        check_start(paths, NAME, component="upgrade", compose_files=["compose.yml"],
                    regenerated=True)


def test_the_upgrades_record_step_refuses_a_rewritten_manifest(box) -> None:
    from boxmunge.commands.upgrade_steps import _record_bind_sources
    paths, project_dir, *_ = box
    _deploy(paths)
    _profile_off(project_dir)
    refusal = _record_bind_sources(paths, NAME)
    assert refusal and "control file manifest.yml changed" in refusal


@pytest.mark.parametrize("tampered", [False, True])
def test_a_manifest_the_upgrade_migrates_is_renewed_only_from_the_recorded_one(
        box, tampered) -> None:
    """migrate_one rewrites manifest.yml itself: its new hash is recorded
    when the manifest it migrated was the one deployed, and not otherwise."""
    from boxmunge.upgrade_exclusions import migrate_one
    paths, project_dir, *_ = box
    _deploy(paths)
    if tampered:
        _profile_off(project_dir)
    assert migrate_one(paths, project_dir) == "written"
    if tampered:
        with pytest.raises(ComposeRefused, match="control file manifest.yml changed"):
            _upgrade_record(paths)
    else:
        _upgrade_record(paths)
        _restart(paths)


def test_the_record_holds_exactly_the_hashes_that_were_checked(box, monkeypatch) -> None:
    """A container rewriting a file between the check and the record must
    not get its version recorded: the record is the checked hashes."""
    from boxmunge import bind_sources
    paths, project_dir, *_ = box
    _deploy(paths)
    before = _record(paths)["control"]
    real = bind_sources.check_kept_control

    def check_then_tamper(*args, **kwargs):
        checked = real(*args, **kwargs)
        _profile_off(project_dir)
        return checked
    monkeypatch.setattr(bind_sources, "check_kept_control", check_then_tamper)
    _upgrade_record(paths)
    assert _record(paths)["control"]["manifest.yml"] == before["manifest.yml"]
    with pytest.raises(ComposeRefused, match="control file manifest.yml changed"):
        _restart(paths)


def test_a_paused_projects_refusal_names_the_way_a_deploy_can_run(box) -> None:
    """A deploy is refused while the project is paused, and resume runs the
    same check: the way out is to hand the pause to the redeploy."""
    from boxmunge.commands.upgrade_offline import offline_exit
    from boxmunge.pause import mark_pause_complete, write_paused_state
    paths, project_dir, *_ = box
    _deploy(paths)
    write_paused_state(NAME, paths)
    mark_pause_complete(NAME, paths)
    _profile_off(project_dir)
    way = "`boxmunge resume shop --no-start`, then `boxmunge prod-deploy shop --redeploy`"
    with pytest.raises(ComposeRefused) as e:
        _upgrade_record(paths)
    assert way in str(e.value)
    assert way in offline_exit(paths, NAME)
