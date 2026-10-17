"""project.get reports an open install and a stage left by 0.10.1."""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from boxmunge.api.actions.project import PROJECT_VIEW, _project_get
from boxmunge.api.schema import validate
from boxmunge.legacy_stage import EvidenceError, legacy_staging_state
from boxmunge.release_txn import ABANDONING, advance, mark_abandon, open_txn, txn_path
from boxmunge.state import StateError
from tests.legacy_helpers import legacy_bundle_stage
from tests.stage_helpers import V1, prod_and_stage

EVIDENCE = "boxmunge.api.actions.project.evidence"


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
    assert view["legacy_stage"] is None


def test_an_abandoning_install_is_reported_with_its_phase(paths) -> None:
    prod_and_stage(paths)
    txn = open_txn(paths, "myapp", source="bundle", ref="myapp-x",
                   replaced_ref=f"myapp-{V1}", staged_id=None, snapshot="")
    mark_abandon(paths, "myapp", advance(paths, "myapp", txn, "installed"), ABANDONING)
    assert _get(paths)["install"]["phase"] == ABANDONING


def test_no_install_and_no_legacy_stage(paths) -> None:
    prod_and_stage(paths)
    view = _get(paths)
    assert view["install"] is None and view["legacy_stage"] is None


def test_an_unreadable_install_record_is_a_state_error(paths) -> None:
    prod_and_stage(paths)
    txn_path(paths, "myapp").write_text("{not json")
    with pytest.raises(StateError, match="install record of myapp is unreadable"):
        _project_get({"project": "myapp"}, _Ctx(paths))


def test_legacy_stage_is_reported(paths) -> None:
    legacy_bundle_stage(paths)
    with patch(EVIDENCE, side_effect=EvidenceError("x")):
        view = _get(paths)
    assert view["legacy_stage"] == {"kind": "bundle", "evidence": "unknown"}
    assert view["install"] is None


def test_legacy_evidence_is_reported_when_it_can_be_read(paths) -> None:
    legacy_bundle_stage(paths)
    long_ago = {"myapp-web-1": datetime(2000, 1, 1, tzinfo=timezone.utc)}
    with patch("boxmunge.legacy_stage.docker_containers.created_times",
               return_value=long_ago):
        assert _get(paths)["legacy_stage"] == {"kind": "bundle", "evidence": "untouched"}
    with patch("boxmunge.legacy_stage.docker_containers.created_times",
               return_value={"myapp-web-1": datetime.now(timezone.utc)}):
        assert _get(paths)["legacy_stage"] == {"kind": "bundle", "evidence": "recreated"}


def test_evidence_that_raises_oserror_is_unknown(paths) -> None:
    legacy_bundle_stage(paths)
    with patch(EVIDENCE, side_effect=PermissionError(13, "Permission denied")):
        assert _get(paths)["legacy_stage"] == {"kind": "bundle", "evidence": "unknown"}


def test_a_leftover_has_no_evidence(paths) -> None:
    prod_and_stage(paths)
    legacy_staging_state(paths, "myapp").parent.mkdir(parents=True, exist_ok=True)
    legacy_staging_state(paths, "myapp").write_text('{"active": true, "ref": "x"}\n')
    with patch(EVIDENCE) as evidence:
        assert _get(paths)["legacy_stage"] == {"kind": "leftover", "evidence": None}
    evidence.assert_not_called()


def test_a_detection_that_cannot_tell_is_a_state_error(paths) -> None:
    legacy_bundle_stage(paths)
    with patch("boxmunge.api.actions.project.legacy_stage",
               side_effect=PermissionError(13, "Permission denied")), \
            pytest.raises(StateError, match="cannot tell whether a 0.10.1 stage"):
        _project_get({"project": "myapp"}, _Ctx(paths))
