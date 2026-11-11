# SPDX-License-Identifier: Apache-2.0
"""Files root reads by name in deploy-writable places are read without
following a link and never block on a FIFO: open_regular_nofollow opens
O_NONBLOCK (cleared once the file is known to be regular), and the
upgrade's reads of an old-layout stage's state and record and install.json
go through read_text_nofollow."""
from __future__ import annotations

import fcntl
import os
import threading
from pathlib import Path
from typing import Callable

import pytest

from boxmunge import unresolved_stage
from boxmunge.data_dirs import ReleaseStateError
from boxmunge.fs_nofollow import open_regular_nofollow, read_text_nofollow
from boxmunge.release_txn import load_txn, txn_path

P = "myapp"
PRE0101 = f"  - {P}: a release staged by a boxmunge release before 0.10.1 is unresolved (pre0101)"


def _stage_refusal(paths) -> str | None:
    return unresolved_stage.refusal(paths, [P], "0.11.6")


def _within(fn: Callable[[], object], fifo: Path, seconds: float = 5.0) -> object:
    """fn's result or exception; a call still blocked on `fifo` after
    `seconds` is released (opening it read-write unblocks a blocked reader
    or writer) and fails the test."""
    out: dict[str, object] = {}

    def run() -> None:
        try:
            out["value"] = fn()
        except BaseException as e:  # re-raised in the test's thread
            out["error"] = e
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        release = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
        worker.join(seconds)
        os.close(release)
        pytest.fail(f"blocked on the FIFO at {fifo}")
    if "error" in out:
        raise out["error"]  # type: ignore[misc]
    return out.get("value")


def _fifo(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(path)
    return path


def test_a_fifo_is_refused_without_blocking(tmp_path) -> None:
    fifo = _fifo(tmp_path / "f")
    with pytest.raises(OSError, match="not a plain regular file"):
        _within(lambda: open_regular_nofollow(fifo, os.O_RDONLY), fifo)


def test_a_regular_file_is_opened_blocking(tmp_path) -> None:
    path = tmp_path / "f"
    path.write_text("x")
    fd = open_regular_nofollow(path, os.O_RDONLY)
    try:
        assert not fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NONBLOCK
    finally:
        os.close(fd)
    assert read_text_nofollow(path) == "x"


def test_a_fifo_state_file_counts_as_a_stage_without_blocking(paths) -> None:
    paths.project_dir(P).mkdir(parents=True)
    fifo = _fifo(paths.state / "staging" / f"{P}.json")
    assert PRE0101 in _within(lambda: _stage_refusal(paths), fifo)


def test_a_linked_state_file_is_not_read_through(paths, tmp_path) -> None:
    """A link to a file saying inactive must not hide the stage."""
    paths.project_dir(P).mkdir(parents=True)
    target = tmp_path / "inactive.json"
    target.write_text('{"active": false}')
    state = paths.state / "staging" / f"{P}.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.symlink_to(target)
    assert PRE0101 in _stage_refusal(paths)


@pytest.mark.parametrize("make", ["fifo", "link"])
def test_an_unusable_record_file_refuses_the_upgrade(paths, tmp_path, make) -> None:
    paths.project_dir(P).mkdir(parents=True)
    path = paths.state / "legacy-stages.json"
    if make == "fifo":
        _fifo(path)
    else:
        (tmp_path / "records.json").write_text("{}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(tmp_path / "records.json")
    text = _within(lambda: _stage_refusal(paths), path)
    assert text.startswith("Cannot tell which projects hold a release") and str(path) in text


@pytest.mark.parametrize("make", ["fifo", "link"])
def test_an_unusable_install_record_is_a_release_state_error(paths, tmp_path, make) -> None:
    path = txn_path(paths, P)
    if make == "fifo":
        _fifo(path)
    else:
        (tmp_path / "install.json").write_text("{}")
        path.parent.mkdir(parents=True)
        path.symlink_to(tmp_path / "install.json")
    with pytest.raises(ReleaseStateError, match="Cannot read"):
        _within(lambda: load_txn(paths, P), path)
