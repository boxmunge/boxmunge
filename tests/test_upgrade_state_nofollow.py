# SPDX-License-Identifier: Apache-2.0
"""upgrade-state/ is root:deploy 0770, so deploy can plant a link or a FIFO
at any name in it. Every root open there (upgrade.lock, probation.json,
blocklist.json) refuses both without blocking, naming the file and saying
to remove it."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from boxmunge.commands.auto_update_cmd import run_auto_update
from boxmunge.upgrade_state import (
    UpgradeStateError, add_to_blocklist, is_blocklisted, read_probation, upgrade_lock,
    write_probation,
)
from tests.test_root_reads_nofollow import _fifo, _within

KINDS = ["fifo", "link", "dangling-link"]


def _plant(path: Path, kind: str, tmp_path: Path) -> Path:
    """A FIFO, a link to a file holding valid JSON, or a link to nothing at
    ``path``; returns the file a link points at (or the FIFO)."""
    if kind == "fifo":
        return _fifo(path)
    target = tmp_path / f"target-{path.name}"
    if kind == "link":
        target.write_text("{}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(target)
    return target


def _lock(paths) -> None:
    with upgrade_lock(paths):
        pass


@pytest.mark.parametrize("which", ["upgrade_lock", "legacy_upgrade_lock"])
@pytest.mark.parametrize("kind", KINDS)
def test_upgrade_lock_refuses_a_planted_file(paths, tmp_path, kind, which) -> None:
    lock = getattr(paths, which)
    planted = _plant(lock, kind, tmp_path)
    with pytest.raises(UpgradeStateError, match=f"{lock}.*Remove it"):
        _within(lambda: _lock(paths), planted if kind == "fifo" else lock)
    if kind == "link":
        assert planted.read_text() == "{}"
    if kind == "dangling-link":
        assert not os.path.lexists(planted), "root created the link's target"


@pytest.mark.parametrize("kind", KINDS)
def test_reading_probation_refuses_a_planted_file(paths, tmp_path, kind) -> None:
    planted = _plant(paths.probation, kind, tmp_path)
    with pytest.raises(UpgradeStateError, match=f"{paths.probation}.*Remove it"):
        _within(lambda: read_probation(paths), planted)


@pytest.mark.parametrize("kind", KINDS)
def test_reading_the_blocklist_refuses_a_planted_file(paths, tmp_path, kind) -> None:
    planted = _plant(paths.blocklist, kind, tmp_path)
    with pytest.raises(UpgradeStateError, match=f"{paths.blocklist}.*Remove it"):
        _within(lambda: is_blocklisted(paths, "1.2.3"), planted)
    with pytest.raises(UpgradeStateError):
        _within(lambda: add_to_blocklist(paths, "1.2.3", "x"), planted)
    if kind == "link":
        assert planted.read_text() == "{}"


@pytest.mark.parametrize("kind", ["fifo", "link"])
def test_writing_probation_replaces_a_planted_file_without_opening_it(
        paths, tmp_path, kind) -> None:
    """rename(2) replaces the name itself: a link's target is untouched and
    a FIFO never opened. Refusing instead would let deploy fail the step
    after the venv swap and so force a rollback to the older release."""
    planted = _plant(paths.probation, kind, tmp_path)
    _within(lambda: write_probation(paths, "1.2.3", "a"), planted)
    assert not paths.probation.is_symlink()
    assert read_probation(paths)["version"] == "1.2.3"
    if kind == "link":
        assert planted.read_text() == "{}"


def test_auto_update_reports_a_planted_lock(paths, tmp_path, capsys, monkeypatch) -> None:
    from datetime import timedelta
    from boxmunge.os_updates import OsUpdateStatus
    monkeypatch.setattr("boxmunge.os_updates.inspect_os_updates",
                        lambda: OsUpdateStatus(stamp_age=timedelta(hours=1)))
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n")
    fifo = _plant(paths.upgrade_lock, "fifo", tmp_path)
    assert _within(lambda: run_auto_update(paths), fifo) == 1
    err = capsys.readouterr().err
    assert f"{paths.upgrade_lock}" in err and "Remove it" in err


def test_a_blocklist_that_is_not_utf8_is_a_named_error(paths) -> None:
    paths.blocklist.parent.mkdir(parents=True, exist_ok=True)
    paths.blocklist.write_bytes(b'{"\xff": {}}')
    with pytest.raises(UpgradeStateError, match=f"{paths.blocklist} is not UTF-8"):
        is_blocklisted(paths, "1.2.3")


def test_discovery_reports_a_planted_blocklist_as_an_error_action(
        paths, tmp_path, capsys) -> None:
    """The shim shows the message of an error action; a traceback would
    reach it only as "Discovery failed"."""
    import json
    from unittest.mock import patch
    from boxmunge.commands.discover_update_cmd import cmd_discover_update
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n")
    fifo = _plant(paths.blocklist, "fifo", tmp_path)
    candidate = {"version": "9.9.9", "class": "security", "url": "https://example.com/x"}
    with patch("boxmunge.commands.discover_update_cmd.BoxPaths", return_value=paths), \
            patch("boxmunge.upgrade_discovery.read_installed_version", return_value="0.3.5"), \
            patch("boxmunge.upgrade_discovery._check_endpoint", return_value={}), \
            patch("boxmunge.upgrade_discovery._read_endpoint", return_value=(candidate, None, [])):
        with pytest.raises(SystemExit) as exc:
            _within(lambda: cmd_discover_update(["--json"]), fifo)
    assert exc.value.code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["action"] == "error"
    assert str(paths.blocklist) in out["message"] and "Remove it" in out["message"]


@pytest.mark.parametrize("which", ["upgrade_lock", "legacy_upgrade_lock"])
def test_upgrade_lock_refuses_a_lock_file_of_another_user(paths, monkeypatch, which) -> None:
    """Deploy can unlink root's legacy lock and hold a flock on its own file
    at the name: every taker would then wait on deploy, silently. A lock file
    the taker does not own is refused, naming it."""
    lock = getattr(paths, which)
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.touch()
    foreign = os.stat(lock)
    real_fstat = os.fstat

    def fstat(fd):  # the planted file, as another user's
        st = real_fstat(fd)
        if (st.st_dev, st.st_ino) != (foreign.st_dev, foreign.st_ino):
            return st
        return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid + 1,
                               *st[5:10]))
    monkeypatch.setattr(os, "fstat", fstat)
    with pytest.raises(UpgradeStateError, match=f"{lock} is owned by uid {foreign.st_uid + 1}.*Remove it"):
        _lock(paths)


def test_upgrade_lock_makes_a_0644_legacy_lock_0600(paths) -> None:
    """Shims up to 0.10.1 created the legacy lock 0644: deploy could open it
    read-only and hold a flock on it. Taking the locks closes it to others."""
    paths.legacy_upgrade_lock.parent.mkdir(parents=True, exist_ok=True)
    paths.legacy_upgrade_lock.touch()
    os.chmod(paths.legacy_upgrade_lock, 0o644)
    _lock(paths)
    assert os.stat(paths.legacy_upgrade_lock).st_mode & 0o777 == 0o600
