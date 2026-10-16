"""The install transaction record (.releases/install.json)."""
from __future__ import annotations

import json

import pytest

from boxmunge.data_dirs import ReleaseStateError
from boxmunge.release import mark_live
from boxmunge.release_keep import kept_previous_text
from boxmunge.release_txn import (
    advance, close_txn, load_txn, open_txn, options_text, stale_reason, supersede_txn,
    txn_path,
)

P = "myapp"


@pytest.fixture
def releases(paths):
    rel = paths.project_releases(P)
    rel.mkdir(parents=True)
    mark_live(paths, P, "myapp-v1")
    return rel


def _open(paths, **kw):
    args = {"source": "bundle", "ref": "myapp-v2", "replaced_ref": "myapp-v1",
            "staged_id": None, "snapshot": "snap-1"}
    args.update(kw)
    return open_txn(paths, P, **args)


def test_open_load_round_trip(paths, releases) -> None:
    txn = _open(paths)
    assert load_txn(paths, P) == txn
    doc = json.loads(txn_path(paths, P).read_text())
    assert doc["version"] == 1 and doc["phase"] == "committed"
    assert set(doc["expect"]) == {"live_json_sha256", "previous_json_sha256"}


def test_open_refuses_a_second_transaction(paths, releases) -> None:
    _open(paths)
    with pytest.raises(ReleaseStateError, match="already open"):
        _open(paths)


@pytest.mark.parametrize("bad", ['{"version": 2}', "[]", "not json",
                                 '{"version": 1, "source": "carrier-pigeon"}'])
def test_malformed_record_fails_loudly(paths, releases, bad) -> None:
    txn_path(paths, P).write_text(bad)
    with pytest.raises(ReleaseStateError, match="install.json"):
        load_txn(paths, P)


def test_advance_only_forward_and_only_through_the_sources_phases(paths, releases) -> None:
    txn = advance(paths, P, _open(paths), "previous_kept")
    with pytest.raises(ReleaseStateError):
        advance(paths, P, txn, "committed")
    with pytest.raises(ReleaseStateError):
        advance(paths, P, txn, "data_restored")   # a rollback-only phase


def test_rollback_phases(paths, releases) -> None:
    txn = _open(paths, source="rollback", ref="myapp-v0")
    with pytest.raises(ReleaseStateError):
        advance(paths, P, txn, "previous_kept")
    for phase in ("installed", "data_restored", "hook_started", "switching"):
        txn = advance(paths, P, txn, phase)
    assert load_txn(paths, P).phase == "switching"


def test_advance_rewrites_expect(paths, releases) -> None:
    txn = _open(paths)
    mark_live(paths, P, "myapp-v2")
    txn = advance(paths, P, txn, "previous_kept")
    assert stale_reason(paths, P, txn) is None
    assert txn.expect["live_json_sha256"] != load_txn(paths, P).previous_before


def test_own_steps_are_never_stale(paths, releases) -> None:
    """A crash between mark_live (or the keep) and the next phase write."""
    txn = advance(paths, P, _open(paths), "previous_kept")
    mark_live(paths, P, "myapp-v2")
    assert stale_reason(paths, P, txn) is None
    (releases / "previous.json").write_text(kept_previous_text(txn))
    assert stale_reason(paths, P, txn) is None


def test_outside_change_is_stale(paths, releases) -> None:
    txn = _open(paths)
    mark_live(paths, P, "myapp-v9")   # e.g. 0.10.1 deployed after a platform rollback
    assert "live.json" in stale_reason(paths, P, txn)


def test_supersede_writes_over_in_one_go(paths, releases) -> None:
    old = advance(paths, P, _open(paths), "previous_kept")
    new = supersede_txn(paths, P, old, source="bundle", ref="myapp-v3",
                        replaced_ref=old.replaced_ref, staged_id=None,
                        snapshot=old.snapshot, phase="previous_kept")
    assert load_txn(paths, P) == new and new.id != old.id and new.snapshot == "snap-1"


def test_close_removes_the_record_and_superseded_previous(paths, releases) -> None:
    txn = _open(paths)
    (releases / "previous.superseded").mkdir()
    (releases / "previous.superseded.json").write_text("{}")
    close_txn(paths, P, txn)
    assert load_txn(paths, P) is None
    assert not (releases / "previous.superseded").exists()
    assert not (releases / "previous.superseded.json").exists()


def test_options_text_by_phase(paths, releases) -> None:
    txn = advance(paths, P, _open(paths), "previous_kept")
    text = options_text(P, txn)
    assert "prod-deploy myapp --abandon" in text and "rollback myapp" not in text
    txn = advance(paths, P, advance(paths, P, txn, "installed"), "hook_started")
    text = options_text(P, txn)
    assert "--abandon" not in text and "rollback myapp" in text and "snap-1" in text


def test_a_first_deploy_offers_no_rollback(paths, releases) -> None:
    """A first deploy has no rollback target: a fix is the way out."""
    txn = _open(paths, replaced_ref=None, snapshot="")
    for phase in ("previous_kept", "installed", "hook_started"):
        txn = advance(paths, P, txn, phase)
    text = options_text(P, txn)
    assert "rollback" not in text and "deploy a fix" in text
