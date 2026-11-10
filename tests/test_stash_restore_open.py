"""`stash restore` opens the archive like the upgrade shim does.

stashes/ is deploy-writable, and `stash restore --latest` runs as root (the
shim prints it as the manual remedy). It took the newest-named entry and
opened it by name, so a planted `boxmunge-stash-9999-...` link to an archive
deploy wrote put deploy's config into root-only config/. The archive is now
opened without following a link and must be a plain file of the restoring
user's (root's, on a box), with a single link, as slots.sh's stash_facts
requires of the stash it records.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from boxmunge import stash
from boxmunge.paths import BoxPaths
from boxmunge.stash import StashError, create_stash, restore_stash
from boxmunge.version import write_installed_version

_NEWEST = "boxmunge-stash-9999-01-01T000000Z.tar.gz"


@pytest.fixture
def box(tmp_path: Path) -> tuple[BoxPaths, Path]:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects", "state/deploy", "stashes", "logs"]:
        (paths.root / d).mkdir(parents=True)
    write_installed_version(paths, "0.2.0", "abc1234")
    # An archive "deploy" made, carrying its own config.
    paths.config_file.write_text("hostname: planted\nadmin_email: t@t\n")
    elsewhere = tmp_path / "deploy-owned.tar.gz"
    shutil.move(create_stash(paths).path, elsewhere)
    paths.config_file.write_text("hostname: real\nadmin_email: t@t\n")
    create_stash(paths)
    paths.config_file.write_text("hostname: current\nadmin_email: t@t\n")
    return paths, elsewhere


def test_latest_refuses_a_newest_named_link(box) -> None:
    paths, elsewhere = box
    (paths.stashes / _NEWEST).symlink_to(elsewhere)
    with pytest.raises(StashError, match="symlink"):
        restore_stash(paths)
    assert "hostname: current" in paths.config_file.read_text()


def test_a_named_archive_that_is_a_link_is_refused(box) -> None:
    paths, elsewhere = box
    link = paths.stashes / _NEWEST
    link.symlink_to(elsewhere)
    with pytest.raises(StashError, match="symlink"):
        restore_stash(paths, link)


def test_latest_refuses_a_hard_link(box) -> None:
    paths, elsewhere = box
    os.link(elsewhere, paths.stashes / _NEWEST)
    with pytest.raises(StashError, match="plain file"):
        restore_stash(paths)
    assert "hostname: current" in paths.config_file.read_text()


def test_latest_refuses_a_file_another_user_owns(box, monkeypatch) -> None:
    paths, elsewhere = box
    shutil.move(elsewhere, paths.stashes / _NEWEST)
    real_uid = os.geteuid()
    monkeypatch.setattr(stash.os, "geteuid", lambda: real_uid + 1)
    with pytest.raises(StashError, match="owned by uid"):
        restore_stash(paths)
    assert "hostname: current" in paths.config_file.read_text()


def test_the_refusal_names_the_fix(box) -> None:
    paths, elsewhere = box
    (paths.stashes / _NEWEST).symlink_to(elsewhere)
    with pytest.raises(StashError, match=f"Remove {paths.stashes / _NEWEST}"):
        restore_stash(paths)


def test_latest_still_restores_the_real_stash(box) -> None:
    paths, _ = box
    restore_stash(paths)
    assert "hostname: real" in paths.config_file.read_text()
