# SPDX-License-Identifier: Apache-2.0
"""upgrade-state/ is root:deploy 0770, so deploy can plant a link or a FIFO
at any name in it. Every root open there (upgrade.lock, probation.json,
blocklist.json) refuses both without blocking, naming the file and saying
to remove it, and legacy-stage's probation guard stays fail-closed."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from boxmunge.commands.auto_update_cmd import run_auto_update
from boxmunge.commands.legacy_stage_cmd import run_legacy_stage
from boxmunge.legacy_stage_ops import platform_rollback_possible
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


@pytest.mark.parametrize("kind", KINDS)
def test_the_legacy_stage_probation_guard_fails_closed(paths, tmp_path, kind) -> None:
    planted = _plant(paths.probation, kind, tmp_path)
    why = _within(lambda: platform_rollback_possible(paths), planted)
    assert isinstance(why, str) and "cannot tell whether a platform rollback is possible" in why
    assert f"fix or remove {paths.probation}" in why


def test_legacy_stage_reports_a_planted_lock(paths, tmp_path, capsys) -> None:
    fifo = _plant(paths.upgrade_lock, "fifo", tmp_path)
    assert _within(lambda: run_legacy_stage(paths, "myapp", "discard", False), fifo) == 1
    err = capsys.readouterr().err
    assert f"ERROR: {paths.upgrade_lock}" in err and "Remove it" in err


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
    fifo = _plant(paths.blocklist, "fifo", tmp_path)
    candidate = {"version": "9.9.9", "class": "security", "url": "https://example.com/x"}
    with patch("boxmunge.commands.discover_update_cmd.BoxPaths", return_value=paths), \
            patch("boxmunge.upgrade_discovery.read_installed_version", return_value="0.3.5"), \
            patch("boxmunge.upgrade_discovery._check_endpoint", return_value={}), \
            patch("boxmunge.upgrade_discovery._read_endpoint", return_value=(candidate, None)):
        with pytest.raises(SystemExit) as exc:
            _within(lambda: cmd_discover_update(["--json"]), fifo)
    assert exc.value.code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["action"] == "error"
    assert str(paths.blocklist) in out["message"] and "Remove it" in out["message"]
