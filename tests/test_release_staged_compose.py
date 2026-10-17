"""Production's classification reads the slot's compose.yml without
following a link or blocking on a FIFO (a directory deploy can write)."""
from __future__ import annotations

import os

import pytest

from boxmunge.data_dirs import ReleaseStateError
from boxmunge.release import project_data_dirs
from boxmunge.staged_release import release_dir, slot_dir
from tests.bundle_helpers import SAFE_COMPOSE
from tests.fifo_guard import raised_without_blocking

STAGED = SAFE_COMPOSE + "    volumes: ['./media:/m']\n"


def _slot_compose(paths):
    pdir = paths.project_dir("myapp")
    release = release_dir(slot_dir(paths, "myapp"))
    release.mkdir(parents=True)
    (pdir / "compose.yml").write_text(SAFE_COMPOSE)
    return pdir, release / "compose.yml"


def test_the_staged_view_reads_the_slot_compose(paths) -> None:
    pdir, compose = _slot_compose(paths)
    compose.write_text(STAGED)
    assert project_data_dirs(pdir).staged_rw == {"media"}


def test_a_linked_slot_compose_is_refused(paths, tmp_path) -> None:
    pdir, compose = _slot_compose(paths)
    elsewhere = tmp_path / "compose.yml"
    elsewhere.write_text(STAGED)
    compose.symlink_to(elsewhere)
    with pytest.raises(ReleaseStateError, match=str(compose)):
        project_data_dirs(pdir)


def test_a_fifo_slot_compose_is_refused_without_blocking(paths) -> None:
    pdir, compose = _slot_compose(paths)
    os.mkfifo(compose)
    err = raised_without_blocking(lambda: project_data_dirs(pdir), compose)
    assert isinstance(err, ReleaseStateError) and str(compose) in str(err)


def test_a_linked_release_dir_is_refused(paths, tmp_path) -> None:
    pdir = paths.project_dir("myapp")
    slot = slot_dir(paths, "myapp")
    slot.mkdir(parents=True)
    (pdir / "compose.yml").write_text(SAFE_COMPOSE)
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "compose.yml").write_text(STAGED)
    release_dir(slot).symlink_to(tmp_path / "elsewhere")
    with pytest.raises(ReleaseStateError, match="symbolic link"):
        project_data_dirs(pdir)
