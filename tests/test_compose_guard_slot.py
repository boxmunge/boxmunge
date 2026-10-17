"""Staging starts are checked against the slot and recorded as staging's."""
from __future__ import annotations

from unittest.mock import patch

import pytest
import yaml

from boxmunge.compose_guard import ComposeRefused, compose_up_checked
from boxmunge.staged_release import new_meta, slot_dir, write_meta
from tests.bundle_helpers import manifest_text

P = "myapp"


@pytest.fixture
def slot(paths):
    s = slot_dir(paths, P)
    release = s / "release"
    (release / "appconfig").mkdir(parents=True)
    (release / "manifest.yml").write_text(manifest_text())
    (release / "compose.yml").write_text(yaml.safe_dump({"services": {"web": {
        "image": "nginx", "volumes": ["./appconfig:/etc/app:ro"]}}}))
    (s / "compose.staging-base.yml").write_text(yaml.safe_dump({"services": {"web": {
        "image": "nginx", "volumes": [{"type": "bind", "source": str(release / "appconfig"),
                                       "target": "/etc/app", "read_only": True}]}}}))
    (s / "compose.boxmunge-staging.yml").write_text("services: {}\n")
    write_meta(s, new_meta("bundle", "myapp-v2", None))
    return s


def test_staging_up_runs_from_the_slot_and_records_staging(paths, slot) -> None:
    with patch("boxmunge.compose_guard.compose_up") as up:
        compose_up_checked(paths, P, component="stage", staging=True, record=True,
                           deploying=True)
    args, kwargs = up.call_args
    assert args[0] == slot / "release"
    assert kwargs["project_directory"] == slot / "release"
    assert kwargs["project_name"] == "myapp-staging"
    assert paths.project_bind_record(P, staging=True).exists()
    assert not paths.project_bind_record(P).exists()


def test_staging_mounting_production_is_refused(paths, slot) -> None:
    base = slot / "compose.staging-base.yml"
    doc = yaml.safe_load(base.read_text())
    doc["services"]["web"]["volumes"].append(
        {"type": "bind", "source": str(paths.project_dir(P) / "data"), "target": "/d"})
    base.write_text(yaml.safe_dump(doc))
    (paths.project_dir(P) / "data").mkdir()
    with patch("boxmunge.compose_guard.compose_up") as up, \
            pytest.raises(ComposeRefused, match="which is production's"):
        compose_up_checked(paths, P, component="stage", staging=True, record=True,
                           deploying=True)
    up.assert_not_called()


def test_production_start_needs_compose_files(paths) -> None:
    with pytest.raises(ValueError, match="compose_files"):
        compose_up_checked(paths, P, component="deploy")


def test_staging_start_without_a_slot_is_refused(paths) -> None:
    paths.project_dir(P).mkdir(parents=True)
    with patch("boxmunge.compose_guard.compose_up") as up, pytest.raises(ComposeRefused):
        compose_up_checked(paths, P, component="stage", staging=True, record=True,
                           deploying=True)
    up.assert_not_called()


def test_a_later_staging_start_is_checked_against_staging_record(paths, slot) -> None:
    with patch("boxmunge.compose_guard.compose_up") as up:
        compose_up_checked(paths, P, component="stage", staging=True, record=True,
                           deploying=True)
        compose_up_checked(paths, P, component="stage", staging=True)
        assert up.call_count == 2
        (slot / "compose.boxmunge-staging.yml").write_text("services: {web: {}}\n")
        with pytest.raises(ComposeRefused, match="compose.boxmunge-staging.yml"):
            compose_up_checked(paths, P, component="stage", staging=True)
    assert up.call_count == 2


def _record_staging(paths) -> None:
    with patch("boxmunge.compose_guard.compose_up"):
        compose_up_checked(paths, P, component="stage", staging=True, record=True,
                           deploying=True)


def test_a_production_deploy_during_a_stage_leaves_staging_startable(paths, slot) -> None:
    """Staging's record hashes the slot's control files, not production's."""
    _record_staging(paths)
    pdir = paths.project_dir(P)
    (pdir / "manifest.yml").write_text(manifest_text())
    (pdir / "compose.yml").write_text("services: {web: {image: nginx}}\n")
    (pdir / ".env").write_text("X=1\n")
    with patch("boxmunge.compose_guard.compose_up") as up:
        compose_up_checked(paths, P, component="stage", staging=True)
    up.assert_called_once()


@pytest.mark.parametrize("name, text", [
    ("manifest.yml", manifest_text() + "# edited after stage\n"),
    (".env", "X=1\n"),
])
def test_an_edit_of_the_slots_control_files_is_caught(paths, slot, name, text) -> None:
    _record_staging(paths)
    (slot / "release" / name).write_text(text)
    with patch("boxmunge.compose_guard.compose_up") as up, \
            pytest.raises(ComposeRefused, match=f"staged/release/{name}"):
        compose_up_checked(paths, P, component="stage", staging=True)
    up.assert_not_called()


@pytest.mark.parametrize("extra", [{"compose_files": ["compose.yml"]}, {"txn": "01X"}])
def test_production_only_arguments_with_staging_are_refused(paths, slot, extra) -> None:
    with patch("boxmunge.compose_guard.compose_up") as up, \
            pytest.raises(ValueError, match="staging"):
        compose_up_checked(paths, P, component="stage", staging=True, **extra)
    up.assert_not_called()


def test_staging_start_with_nothing_staged_says_so(paths) -> None:
    paths.project_dir(P).mkdir(parents=True)
    with patch("boxmunge.compose_guard.compose_up"), \
            pytest.raises(ComposeRefused, match="nothing is staged for myapp"):
        compose_up_checked(paths, P, component="stage", staging=True, record=True,
                           deploying=True)


def test_staging_start_with_an_unreadable_slot_record_is_refused(paths, slot) -> None:
    (slot / "meta.json").write_text("{broken")
    with patch("boxmunge.compose_guard.compose_up") as up, \
            pytest.raises(ComposeRefused, match="meta.json"):
        compose_up_checked(paths, P, component="stage", staging=True, record=True,
                           deploying=True)
    up.assert_not_called()


def test_staging_start_from_a_symlinked_slot_is_refused(paths, slot, tmp_path) -> None:
    moved = tmp_path / "elsewhere"
    slot.rename(moved)
    slot.symlink_to(moved)
    with patch("boxmunge.compose_guard.compose_up") as up, \
            pytest.raises(ComposeRefused, match="not a directory"):
        compose_up_checked(paths, P, component="stage", staging=True, record=True,
                           deploying=True)
    up.assert_not_called()
