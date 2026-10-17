# SPDX-License-Identifier: Apache-2.0
"""Files root reads by name in deploy-writable places are read without
following a link and never block on a FIFO: open_regular_nofollow opens
O_NONBLOCK (cleared once the file is known to be regular), and the
legacy-stage state, record and reflog reads and install.json go through
read_text_nofollow."""
from __future__ import annotations

import fcntl
import os
import threading
from pathlib import Path
from typing import Callable

import pytest

from boxmunge.data_dirs import ReleaseStateError
from boxmunge.fileutil import open_regular_nofollow, read_text_nofollow
from boxmunge.legacy_stage import (
    EvidenceError, LegacyStage, get_record, legacy_stage, legacy_staging_state, records_path,
    stage_time,
)
from boxmunge.release_txn import load_txn, txn_path
from boxmunge.state import StateError

P = "myapp"


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
    fifo = _fifo(legacy_staging_state(paths, P))
    assert _within(lambda: legacy_stage(paths, P), fifo) == LegacyStage("leftover")


def test_a_linked_state_file_is_not_read_through(paths, tmp_path) -> None:
    """A link to a file saying inactive must not hide the stage."""
    paths.project_dir(P).mkdir(parents=True)
    target = tmp_path / "inactive.json"
    target.write_text('{"active": false}')
    state = legacy_staging_state(paths, P)
    state.parent.mkdir(parents=True, exist_ok=True)
    state.symlink_to(target)
    assert legacy_stage(paths, P) == LegacyStage("leftover")


@pytest.mark.parametrize("make", ["fifo", "link"])
def test_an_unusable_record_file_is_a_state_error(paths, tmp_path, make) -> None:
    path = records_path(paths)
    if make == "fifo":
        _fifo(path)
    else:
        (tmp_path / "records.json").write_text("{}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(tmp_path / "records.json")
    with pytest.raises(StateError, match="fix or remove it"):
        _within(lambda: get_record(paths, P), path)


@pytest.mark.parametrize("make", ["fifo", "link"])
def test_an_unusable_reflog_is_evidence_error(paths, tmp_path, make) -> None:
    reflog = paths.project_dir(P) / "repo" / ".git" / "logs" / "HEAD"
    if make == "fifo":
        _fifo(reflog)
    else:
        (tmp_path / "zero").write_text("0 0 t <t@example.com> 1700000000 +0000\tcheckout: x\n")
        reflog.parent.mkdir(parents=True)
        reflog.symlink_to(tmp_path / "zero")
    with pytest.raises(EvidenceError, match="cannot read"):
        _within(lambda: stage_time(paths, P, LegacyStage("git")), reflog)


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
