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
