# SPDX-License-Identifier: Apache-2.0
"""A project's `.releases/` records are deploy-writable, and root reads them
(check-all, backup's retention, rollback): previous.json and live.json
(release._read_meta, release_txn's fingerprints), data-dirs.json
(data_dirs._load_record) and the kept pairing (release_keep). A FIFO there
must not block the reader, a symlink must not be read through, and a file
that is not UTF-8 is a ReleaseStateError like any other unreadable record,
so a backup warns rather than aborting."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from boxmunge.data_dirs import ReleaseStateError, _load_record, record_path
from boxmunge.release import load_previous_release, previous_dir
from boxmunge.release_keep import ensure_kept_pairing, kept_previous_text
from boxmunge.release_txn import current_expect
from tests.fifo_guard import raised_without_blocking

P = "p"
META = {"ref": "p-v1", "data_snapshot": "s", "replaced_at": "t", "replaced_by": "deploy"}


def _previous_json(paths) -> Path:
    previous_dir(paths, P).mkdir(parents=True)
    return paths.project_releases(P) / "previous.json"


def _plant(path: Path, make: str, tmp_path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if make == "fifo":
        os.mkfifo(path)
    elif make == "link":
        target = tmp_path / "planted"
        target.write_bytes(content)
        path.symlink_to(target)
    else:
        path.write_bytes(b"\xff\xfe not utf-8")


@pytest.mark.parametrize("make", ["fifo", "link", "not-utf8"])
def test_previous_json(paths, tmp_path, make) -> None:
    path = _previous_json(paths)
    _plant(path, make, tmp_path, json.dumps(META).encode())
    err = raised_without_blocking(lambda: load_previous_release(paths, P), path)
    assert isinstance(err, ReleaseStateError) and str(path) in str(err)


@pytest.mark.parametrize("make", ["fifo", "link", "not-utf8"])
def test_data_dirs_record(paths, tmp_path, make) -> None:
    project_dir = paths.project_dir(P)
    path = record_path(project_dir)
    _plant(path, make, tmp_path, json.dumps({"version": 1, "data_dirs": []}).encode())
    err = raised_without_blocking(lambda: _load_record(project_dir), path)
    assert isinstance(err, ReleaseStateError) and str(path) in str(err)


@pytest.mark.parametrize("make", ["fifo", "link"])
def test_the_install_fingerprints(paths, tmp_path, make) -> None:
    path = _previous_json(paths)
    _plant(path, make, tmp_path, b"{}")
    err = raised_without_blocking(lambda: current_expect(paths, P), path)
    assert isinstance(err, ReleaseStateError) and str(path) in str(err)


@pytest.mark.parametrize("make", ["fifo", "link"])
def test_the_kept_pairing_replaces_what_is_planted(paths, tmp_path, make) -> None:
    """ensure_kept_pairing's job is to write previous.json as the install
    says: a link or FIFO there is not read through, and is replaced."""
    path = _previous_json(paths)
    txn = MagicMock(source="bundle", replaced_ref="p-v1", abandoning=False,
                    snapshot="s", started_at="t", ref="p-v2", reached=lambda phase: True)
    text = kept_previous_text(txn)
    _plant(path, make, tmp_path, text.encode())
    worker = threading.Thread(target=ensure_kept_pairing, args=(paths, P, txn), daemon=True)
    worker.start()
    worker.join(5)
    if worker.is_alive():
        os.close(os.open(path, os.O_RDWR | os.O_NONBLOCK))
        pytest.fail("ensure_kept_pairing blocked on the FIFO")
    assert not path.is_symlink() and path.is_file()
    assert path.read_text() == text
