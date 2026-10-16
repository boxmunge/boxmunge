"""The keep with a superseded previous release, and its round trip."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge import release_keep
from boxmunge.release import mark_live
from boxmunge.release_keep import keep_previous_release_txn, restore_superseded
from boxmunge.release_txn import open_txn
from tests.bundle_helpers import tree_snapshot

P = "myapp"


@pytest.fixture
def project(paths):
    pdir = paths.project_dir(P)
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text("project: myapp\n")
    (pdir / "compose.yml").write_text("services: {web: {image: nginx}}\n")
    (pdir / "VERSION").write_text("v2-live\n")
    mark_live(paths, P, "myapp-v2")
    old = paths.project_releases(P) / "previous"
    old.mkdir()
    (old / "VERSION").write_text("v1\n")
    (paths.project_releases(P) / "previous.json").write_text('{"ref": "myapp-v1"}\n')
    # Every deployed project has its data-dir record; without one the keep
    # starts it (deliberately, and not undone by a restore).
    (paths.project_releases(P) / "data-dirs.json").write_text('{"version": 1, "data_dirs": []}\n')
    return pdir


def _txn(paths):
    return open_txn(paths, P, source="bundle", ref="myapp-v3", replaced_ref="myapp-v2",
                    staged_id=None, snapshot="snap")


def test_keep_moves_the_old_previous_aside(paths, project) -> None:
    txn = _txn(paths)
    keep_previous_release_txn(paths, P, txn, None)
    rel = paths.project_releases(P)
    assert (rel / "previous" / "VERSION").read_text() == "v2-live\n"
    assert (rel / "previous.superseded" / "VERSION").read_text() == "v1\n"
    assert (rel / "previous.json").read_text() == release_keep.kept_previous_text(txn)


@pytest.mark.parametrize("fail_at", range(4))
def test_keep_failure_at_each_step_round_trips(paths, project, fail_at) -> None:
    """Review Focus 4: whichever step fails (disk full, EIO), restoring the
    superseded previous gives back exactly what was there."""
    rel = paths.project_releases(P)
    before = tree_snapshot(rel)
    txn = _txn(paths)
    before_txn = tree_snapshot(rel)
    calls = {"n": 0}
    real = {"dir": release_keep.durable_rename_dir, "file": release_keep.durable_rename,
            "write": release_keep.atomic_write_text}

    def step(kind):
        def run(*a, **kw):
            if calls["n"] == fail_at:
                raise OSError(28, "No space left on device")
            calls["n"] += 1
            return real[kind](*a, **kw)
        return run

    with patch.object(release_keep, "durable_rename_dir", step("dir")), \
            patch.object(release_keep, "durable_rename", step("file")), \
            patch.object(release_keep, "atomic_write_text", step("write")), \
            pytest.raises(OSError):
        keep_previous_release_txn(paths, P, txn, None)
    restore_superseded(paths, P, txn)
    assert tree_snapshot(rel) == before_txn
    assert {k: v for k, v in before.items()} == {
        k: v for k, v in tree_snapshot(rel).items() if k != "install.json"}


def test_restore_superseded_is_idempotent(paths, project) -> None:
    txn = _txn(paths)
    keep_previous_release_txn(paths, P, txn, None)
    restore_superseded(paths, P, txn)
    restore_superseded(paths, P, txn)
    assert (paths.project_releases(P) / "previous" / "VERSION").read_text() == "v1\n"


def test_first_keep_with_no_previous_is_undone_completely(paths, project) -> None:
    rel = paths.project_releases(P)
    release_keep.discard_dir(rel / "previous")
    (rel / "previous.json").unlink()
    txn = _txn(paths)
    keep_previous_release_txn(paths, P, txn, None)
    restore_superseded(paths, P, txn)
    assert not (rel / "previous").exists() and not (rel / "previous.json").exists()


def test_keep_syncs_the_copy_before_renaming_it(paths, project) -> None:
    order: list[str] = []
    with patch.object(release_keep, "sync_tree", lambda p: order.append(f"sync {p.name}")), \
            patch.object(release_keep, "durable_rename_dir",
                         lambda s, d: (order.append(f"rename {s.name}"), s.rename(d))):
        keep_previous_release_txn(paths, P, _txn(paths), None)
    assert order.index("sync previous.building") < order.index("rename previous.building")
