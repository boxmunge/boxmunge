"""project.get reports an open install."""
from __future__ import annotations

import pytest

from boxmunge.api.actions.project import PROJECT_VIEW, _project_get
from boxmunge.api.schema import validate
from boxmunge.release_txn import ABANDONING, advance, mark_abandon, open_txn, txn_path
from boxmunge.state import StateError
from tests.stage_helpers import V1, prod_and_stage


class _Ctx:
    def __init__(self, paths):
        self.paths = paths


def _get(paths) -> dict:
    view = _project_get({"project": "myapp"}, _Ctx(paths))
    assert validate(PROJECT_VIEW, view) == []
    return view


def test_open_install_is_reported(paths) -> None:
    prod_and_stage(paths)
    txn = open_txn(paths, "myapp", source="bundle", ref="myapp-x",
                   replaced_ref=f"myapp-{V1}", staged_id=None, snapshot="")
    view = _get(paths)
    assert view["install"] == {"id": txn.id, "source": "bundle", "ref": "myapp-x",
                               "phase": "committed"}


def test_an_abandoning_install_is_reported_with_its_phase(paths) -> None:
    prod_and_stage(paths)
    txn = open_txn(paths, "myapp", source="bundle", ref="myapp-x",
                   replaced_ref=f"myapp-{V1}", staged_id=None, snapshot="")
    mark_abandon(paths, "myapp", advance(paths, "myapp", txn, "installed"), ABANDONING)
    assert _get(paths)["install"]["phase"] == ABANDONING


def test_no_install(paths) -> None:
    prod_and_stage(paths)
    assert _get(paths)["install"] is None


def test_an_unreadable_install_record_is_a_state_error(paths) -> None:
    prod_and_stage(paths)
    txn_path(paths, "myapp").write_text("{not json")
    with pytest.raises(StateError, match="install record of myapp is unreadable"):
        _project_get({"project": "myapp"}, _Ctx(paths))
