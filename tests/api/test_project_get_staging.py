"""project.get reports the stage from the slot."""
from __future__ import annotations

import pytest

from boxmunge.api.actions.project import _project_get
from boxmunge.staged_release import load_slot, slot_dir, update_meta
from boxmunge.state import StateError
from tests.stage_helpers import prod_and_stage


class _Ctx:
    def __init__(self, paths):
        self.paths = paths


def test_staging_comes_from_the_slot(paths) -> None:
    prod_and_stage(paths)
    meta = load_slot(paths, "myapp")
    view = _project_get({"project": "myapp"}, _Ctx(paths))
    assert view["staging"] == {"active": True, "id": meta.id, "ref": meta.ref, "state": "ready"}


def test_a_starting_slot_is_reported_as_such(paths) -> None:
    prod_and_stage(paths)
    meta = update_meta(paths, "myapp", load_slot(paths, "myapp"), state="starting")
    view = _project_get({"project": "myapp"}, _Ctx(paths))
    assert view["staging"]["state"] == "starting" and view["staging"]["id"] == meta.id


def test_no_slot(paths) -> None:
    from tests.bundle_helpers import place_bundle
    from tests.txn_helpers import docker_off
    from boxmunge.commands.deploy import run_deploy
    from boxmunge.project_registry import add_project
    add_project("myapp", paths)
    place_bundle(paths)
    with docker_off():
        run_deploy("myapp", paths)
    view = _project_get({"project": "myapp"}, _Ctx(paths))
    assert view["staging"] == {"active": False, "id": None, "ref": None, "state": None}


def test_an_unreadable_slot_is_a_state_error(paths) -> None:
    prod_and_stage(paths)
    (slot_dir(paths, "myapp") / "meta.json").write_text("{not json")
    with pytest.raises(StateError, match="staged release of myapp is unreadable"):
        _project_get({"project": "myapp"}, _Ctx(paths))
