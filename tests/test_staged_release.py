"""The slot: <p>/.releases/staged/ (meta, swap, debris, compose target)."""
from __future__ import annotations

import json
import os

import pytest

from boxmunge.staged_release import (
    SlotError, building_dir, drop_slot, load_slot, manual_teardown, new_meta,
    release_dir, slot_dir, staging_target, swap_in, sweep_debris, update_meta, write_meta,
)

P = "myapp"


def _build(paths, ref="myapp-v2"):
    building = building_dir(paths, P)
    (release_dir(building)).mkdir(parents=True)
    (release_dir(building) / "VERSION").write_text(ref)
    meta = new_meta("bundle", ref, "ab" * 32)
    write_meta(building, meta)
    return meta


def test_meta_round_trip_and_swap(paths) -> None:
    meta = _build(paths)
    swap_in(paths, P)
    assert load_slot(paths, P) == meta and meta.state == "starting"
    assert not building_dir(paths, P).exists()
    doc = json.loads((slot_dir(paths, P) / "meta.json").read_text())
    assert doc["version"] == 1 and doc["production_stopped"] is None


def test_restage_swap_replaces_the_old_slot(paths) -> None:
    _build(paths, "myapp-v2")
    swap_in(paths, P)
    new = _build(paths, "myapp-v3")
    swap_in(paths, P)
    assert load_slot(paths, P).id == new.id
    assert (release_dir(slot_dir(paths, P)) / "VERSION").read_text() == "myapp-v3"
    assert sorted(os.listdir(paths.project_releases(P))) == ["staged"]


@pytest.mark.parametrize("bad", ["", "{}", '{"version": 2}', "[1]",
                                 json.dumps({"version": 1, "id": "x", "kind": "zip", "ref": "r",
                                             "bundle_sha256": None, "staged_at": "t",
                                             "state": "ready"})])
def test_unreadable_meta_is_a_slot_error(paths, bad) -> None:
    _build(paths)
    swap_in(paths, P)
    (slot_dir(paths, P) / "meta.json").write_text(bad)
    with pytest.raises(SlotError, match="meta.json"):
        load_slot(paths, P)


@pytest.mark.parametrize("made", ["x-staging", ["foo"], ["a/b-staging"], ["-staging"], [1]])
def test_a_malformed_made_list_is_a_slot_error(paths, made) -> None:
    _build(paths)
    swap_in(paths, P)
    path = slot_dir(paths, P) / "meta.json"
    path.write_text(json.dumps({**json.loads(path.read_text()), "made": made}))
    with pytest.raises(SlotError, match="made"):
        load_slot(paths, P)


def test_made_round_trips(paths) -> None:
    building = building_dir(paths, P)
    release_dir(building).mkdir(parents=True)
    meta = new_meta("bundle", "myapp-v2", None, made=("media-staging",))
    write_meta(building, meta)
    swap_in(paths, P)
    assert load_slot(paths, P).made == ("media-staging",)


def test_symlinked_slot_is_a_slot_error(paths, tmp_path) -> None:
    paths.project_releases(P).mkdir(parents=True)
    os.symlink(tmp_path, slot_dir(paths, P))
    with pytest.raises(SlotError, match="not a directory"):
        load_slot(paths, P)


def test_update_meta_and_clear_marker(paths) -> None:
    from boxmunge.staged_release import clear_production_stopped
    meta = _build(paths)
    swap_in(paths, P)
    update_meta(paths, P, meta, production_stopped={"at": "t", "containers": ["c1"]})
    clear_production_stopped(paths, P)
    assert load_slot(paths, P).production_stopped is None


@pytest.mark.parametrize("marker", [{}, [], "c1", {"at": "t"}, {"containers": ["c1"]},
                                    {"at": 1, "containers": ["c1"]},
                                    {"at": "t", "containers": "c1"},
                                    {"at": "t", "containers": [1]},
                                    {"at": "t", "containers": []}])
def test_a_malformed_marker_is_a_slot_error(paths, marker) -> None:
    _build(paths)
    swap_in(paths, P)
    path = slot_dir(paths, P) / "meta.json"
    doc = json.loads(path.read_text())
    path.write_text(json.dumps({**doc, "production_stopped": marker}))
    with pytest.raises(SlotError, match="meta.json.*production_stopped"):
        load_slot(paths, P)


def test_a_marker_records_some_container(paths) -> None:
    from boxmunge.production_stopped import mark_stopped
    meta = _build(paths)
    swap_in(paths, P)
    with pytest.raises(ValueError, match="no container"):
        mark_stopped(paths, P, meta, [])


def test_sweep_removes_building_and_discarded_debris(paths) -> None:
    rel = paths.project_releases(P)
    (rel / "staged.building" / "release").mkdir(parents=True)
    (rel / "staged.discarded").mkdir()
    (rel / ".isolation-abc").mkdir()
    (rel / "live.json").write_text("{}")
    sweep_debris(paths, P)
    assert sorted(os.listdir(rel)) == ["live.json"]


def test_staging_target(paths) -> None:
    _build(paths)
    swap_in(paths, P)
    t = staging_target(paths, P)
    slot = slot_dir(paths, P)
    assert t.cwd == t.project_directory == slot / "release"
    assert t.project_name == "myapp-staging" and t.env_file is None
    assert t.files == [str(slot / "compose.staging-base.yml"),
                       str(slot / "compose.boxmunge-staging.yml")]
    (slot / "release" / ".env").write_text("X=1\n")
    assert staging_target(paths, P).env_file == slot / "release" / ".env"


def test_manual_teardown_names_the_project_directory(paths) -> None:
    text = manual_teardown(paths, P)
    assert f"--project-directory {slot_dir(paths, P)}/release" in text
    assert f"rm -rf {slot_dir(paths, P)}" in text and "myapp-staging.conf" in text


def test_drop_slot(paths) -> None:
    _build(paths)
    swap_in(paths, P)
    drop_slot(paths, P)
    assert load_slot(paths, P) is None


def test_leaving_retired_drops_the_switch_result(paths) -> None:
    """Only a retired slot records replace_release's exit code; a slot taken
    back to `starting` (a re-stage over it) must not keep it, or load_slot
    refuses the slot."""
    meta = _build(paths)
    swap_in(paths, P)
    retired = update_meta(paths, P, meta, state="retired", switch_rc=1)
    assert load_slot(paths, P).switch_rc == 1
    update_meta(paths, P, retired, state="starting")
    assert load_slot(paths, P).switch_rc is None
    update_meta(paths, P, retired, cleanup_incomplete="x")
    assert load_slot(paths, P).switch_rc == 1


def test_a_switch_result_passed_with_another_state_is_refused(paths) -> None:
    """Dropping a carried-over result is a reset; dropping one the caller
    passes would lose it silently."""
    meta = _build(paths)
    swap_in(paths, P)
    with pytest.raises(ValueError, match="switch_rc"):
        update_meta(paths, P, meta, state="ready", switch_rc=0)
    with pytest.raises(ValueError, match="switch_rc"):
        update_meta(paths, P, meta, switch_rc=1)  # meta is starting
    update_meta(paths, P, meta, state="ready", switch_rc=None)
    assert load_slot(paths, P).switch_rc is None
