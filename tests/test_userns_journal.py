"""The journal: atomic, root-only, never through a symlink."""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from boxmunge.userns.journal import FORWARD, Journal, JournalError, load_journal, save_journal

S = 1048576
BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap" / "userns.sh"


def test_round_trip_and_phase_order(paths) -> None:
    assert load_journal(paths) is None
    j = Journal(FORWARD, "quiesced", S, items={"volume:a": "moved"}, timers={"t": True},
                setid={"/x": {"bad\udcffname": 0o4755}}, caddyfile_mode=0o640)
    save_journal(paths, j)
    assert load_journal(paths) == j
    assert oct(paths.upgrade_root.stat().st_mode & 0o777) == "0o700"
    assert oct(paths.userns_journal.stat().st_mode & 0o777) == "0o600"
    assert j.reached("prepared") and j.reached("quiesced") and not j.reached("switched")


def test_init_hosts_fresh_install_record_loads(paths) -> None:
    """The exact line bootstrap/userns.sh's userns_journal_committed prints."""
    fmt = re.search(r"printf '(\{\"version\".*?\})\\n'", BOOTSTRAP.read_text()).group(1)
    line = subprocess.run(["bash", "-c", f"printf '{fmt}' {S}"], capture_output=True,
                          text=True, check=True).stdout
    paths.upgrade_root.mkdir(mode=0o700)
    paths.userns_journal.write_text(line + "\n")
    j = load_journal(paths)
    assert (j.direction, j.phase, j.offset, j.fresh_install) == (FORWARD, "committed", S, True)


def test_a_symlinked_journal_is_refused(paths, tmp_path) -> None:
    paths.upgrade_root.mkdir(mode=0o700)
    (tmp_path / "evil.json").write_text("{}")
    os.symlink(tmp_path / "evil.json", paths.userns_journal)
    with pytest.raises(JournalError, match="cannot open"):
        load_journal(paths)


def test_a_group_readable_directory_is_refused(paths) -> None:
    paths.upgrade_root.mkdir(mode=0o750)
    with pytest.raises(JournalError, match="mode 0700"):
        load_journal(paths)


def test_a_linked_directory_is_refused(paths, tmp_path) -> None:
    (tmp_path / "elsewhere").mkdir(mode=0o700)
    os.symlink(tmp_path / "elsewhere", paths.upgrade_root)
    with pytest.raises(JournalError, match="must be a directory"):
        save_journal(paths, Journal(FORWARD, "started", S))


@pytest.mark.parametrize("doc", [
    {"version": 2, "direction": "forward", "phase": "started", "offset": S},
    {"version": 1, "direction": "forward", "phase": "rb-started", "offset": S},
    {"version": 1, "direction": "forward", "phase": "started", "offset": S + 1},
    {"version": 1, "direction": "forward", "phase": "started", "offset": True},
    {"version": 1, "direction": "forward", "phase": "started", "offset": S, "extra": 1},
    {"version": 1, "direction": "forward", "phase": "started", "offset": S, "items": []},
    {"version": 1, "direction": "forward", "phase": "started", "offset": S,
     "caddyfile_mode": True},
    [],
])
def test_malformed_journals_are_refused(paths, doc) -> None:
    paths.upgrade_root.mkdir(mode=0o700)
    paths.userns_journal.write_text(json.dumps(doc))
    with pytest.raises(JournalError):
        load_journal(paths)
