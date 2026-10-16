# SPDX-License-Identifier: Apache-2.0
"""The site journal is deploy-writable; root restores from it.

Every entry must name a site file in the Caddy sites directory, by the name
the entry itself has, and hold what boxmunge writes. Anything else is refused
loudly and never acted on: an entry naming `/etc/...` would otherwise have
root overwrite or delete that file.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.caddy_journal import (
    JOURNAL_DIRNAME, JournalError, commit_sites, remove_site, restore_sites, write_site,
)


@pytest.fixture
def caddy(tmp_path: Path) -> Path:
    (tmp_path / "caddy" / "sites").mkdir(parents=True)
    return tmp_path / "caddy"


@pytest.fixture
def victim(tmp_path: Path) -> Path:
    path = tmp_path / "outside" / "victim"
    path.parent.mkdir()
    path.write_text("root's file\n")
    return path


def _plant(caddy: Path, name: str, record) -> Path:
    journal = caddy / JOURNAL_DIRNAME
    journal.mkdir(exist_ok=True)
    entry = journal / name
    entry.write_text(record if isinstance(record, str) else json.dumps(record))
    return entry


@pytest.mark.parametrize("previous", [None, "pwned\n"])
def test_entry_naming_a_path_outside_the_sites_dir_is_refused(caddy, victim, previous) -> None:
    entry = _plant(caddy, "app.conf.json",
                   {"path": str(victim), "previous": previous, "written": victim.read_text()})
    with pytest.raises(JournalError) as exc:
        restore_sites(caddy)
    assert victim.read_text() == "root's file\n"
    assert str(entry) in str(exc.value) and "Delete" in str(exc.value)


def test_entry_naming_another_site_than_its_own_name_is_refused(caddy) -> None:
    other = caddy / "sites" / "other.conf"
    other.write_text("other\n")
    _plant(caddy, "app.conf.json", {"path": str(other), "previous": None, "written": "other\n"})
    with pytest.raises(JournalError):
        restore_sites(caddy)
    assert other.read_text() == "other\n"


@pytest.mark.parametrize("name", ["..json", ".conf.json", "app.txt.json", "App.conf.json", "a.b.conf.json"])
def test_entry_whose_name_is_not_a_site_file_is_refused(caddy, name) -> None:
    journal = caddy / JOURNAL_DIRNAME
    journal.mkdir()
    entry = journal / Path(name).name
    entry.write_text(json.dumps({"path": str(caddy / "sites" / entry.name[:-5]),
                                 "previous": None, "written": ""}))
    with pytest.raises(JournalError):
        restore_sites(caddy)


def test_site_file_that_is_a_symlink_is_refused(caddy, victim) -> None:
    site = caddy / "sites" / "app.conf"
    site.symlink_to(victim)
    _plant(caddy, "app.conf.json",
           {"path": str(site), "previous": "pwned\n", "written": victim.read_text()})
    with pytest.raises(JournalError, match="symlink"):
        restore_sites(caddy)
    assert victim.read_text() == "root's file\n" and site.is_symlink()


def test_entry_that_is_a_symlink_is_refused(caddy, tmp_path) -> None:
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps({"path": str(caddy / "sites" / "app.conf"),
                                  "previous": None, "written": ""}))
    (caddy / JOURNAL_DIRNAME).mkdir()
    (caddy / JOURNAL_DIRNAME / "app.conf.json").symlink_to(target)
    with pytest.raises(JournalError, match="symlink"):
        restore_sites(caddy)


def test_symlinked_journal_dir_is_refused_by_commit_and_restore(caddy, victim) -> None:
    planted = victim.parent / "keep.json"
    planted.write_text("{}")
    (caddy / JOURNAL_DIRNAME).symlink_to(victim.parent)
    for act in (commit_sites, restore_sites):
        with pytest.raises(JournalError, match="symlink"):
            act(caddy)
    assert planted.exists()


@pytest.mark.parametrize("record", [
    "not json",
    [1, 2],
    {"path": "SITE", "previous": 7, "written": ""},
    {"path": "SITE", "previous": None, "written": None},
    {"path": "SITE", "previous": None},
    {"path": "SITE", "previous": None, "written": "", "extra": 1},
])
def test_entry_of_the_wrong_shape_is_refused(caddy, record) -> None:
    site = caddy / "sites" / "app.conf"
    if isinstance(record, dict):
        record = {k: (str(site) if v == "SITE" else v) for k, v in record.items()}
    _plant(caddy, "app.conf.json", record)
    with pytest.raises(JournalError):
        restore_sites(caddy)


def test_valid_entries_are_restored_alongside_a_refused_one(caddy, victim) -> None:
    sites = caddy / "sites"
    write_site(caddy, sites / "good.conf", "new\n")
    _plant(caddy, "bad.conf.json", {"path": str(victim), "previous": None,
                                    "written": victim.read_text()})
    with pytest.raises(JournalError) as exc:
        restore_sites(caddy)
    assert exc.value.restored == ["good.conf"]
    assert not (sites / "good.conf").exists()
    assert victim.exists()


def test_write_site_refuses_a_planted_entry(caddy, victim) -> None:
    site = caddy / "sites" / "app.conf"
    _plant(caddy, "app.conf.json", {"path": str(victim), "previous": "x", "written": ""})
    with pytest.raises(JournalError):
        write_site(caddy, site, "new\n")
    assert not site.exists()


def test_write_site_refuses_a_path_outside_the_sites_dir(caddy, victim) -> None:
    with pytest.raises(JournalError):
        write_site(caddy, victim, "new\n")
    assert victim.read_text() == "root's file\n"


def test_round_trip_still_restores_and_removes(caddy) -> None:
    site = caddy / "sites" / "app.conf"
    site.write_text("accepted\n")
    write_site(caddy, site, "first\n")
    write_site(caddy, site, "second\n")
    assert restore_sites(caddy) == ["app.conf"]
    assert site.read_text() == "accepted\n"
    write_site(caddy, site, "third\n")
    remove_site(caddy, site)
    assert not site.exists() and restore_sites(caddy) == []


def test_caddy_reload_reports_refused_entries(caddy, victim) -> None:
    from boxmunge.docker import CaddyConfigRejected, caddy_reload
    write_site(caddy, caddy / "sites" / "good.conf", "new\n")
    _plant(caddy, "bad.conf.json", {"path": str(victim), "previous": None,
                                    "written": victim.read_text()})
    with patch("boxmunge.docker.caddy_validate", return_value=False), \
            patch("boxmunge.docker.container_running", return_value=True), \
            pytest.raises(CaddyConfigRejected) as exc:
        caddy_reload(caddy, caddy)
    assert exc.value.restored == ["good.conf"]
    assert "bad.conf.json" in str(exc.value) and victim.exists()


def test_fifo_entry_is_refused_without_blocking(caddy) -> None:
    import os
    (caddy / JOURNAL_DIRNAME).mkdir()
    os.mkfifo(caddy / JOURNAL_DIRNAME / "app.conf.json")
    with pytest.raises(JournalError, match="not a regular file"):
        restore_sites(caddy)


def test_oversized_entry_is_refused(caddy) -> None:
    site = caddy / "sites" / "app.conf"
    _plant(caddy, "app.conf.json", {"path": str(site), "previous": None,
                                    "written": "x" * (5 * 1024 * 1024)})
    with pytest.raises(JournalError, match="larger than"):
        restore_sites(caddy)


@pytest.mark.parametrize("make", ["fifo", "dev_zero_link", "huge"])
def test_reads_never_follow_block_or_exhaust(tmp_path, make) -> None:
    """The reader itself, for a file swapped after the directory checks."""
    import os
    from boxmunge.caddy_journal import MAX_SITE_BYTES, _read
    path = tmp_path / "app.conf"
    if make == "fifo":
        os.mkfifo(path)
    elif make == "dev_zero_link":
        path.symlink_to("/dev/zero")
    else:
        path.write_bytes(b"x" * (MAX_SITE_BYTES + 1))
    with pytest.raises(JournalError):
        _read(path)


def test_write_site_refuses_oversized_content(caddy) -> None:
    from boxmunge.caddy_journal import MAX_SITE_BYTES
    site = caddy / "sites" / "app.conf"
    with pytest.raises(JournalError, match="larger than"):
        write_site(caddy, site, "x" * (MAX_SITE_BYTES + 1))
    assert not site.exists()
