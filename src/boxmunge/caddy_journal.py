# SPDX-License-Identifier: Apache-2.0
"""Journal of Caddy site files written since Caddy last accepted its config.

A deploy writes its site file first and asks Caddy to validate and reload
later. If that validation fails, the bad file must not stay on disk: the
next reload by any project would fail on it too, and a Caddy restart would
refuse to start. So before a site file is overwritten, its last-validated
content (or its absence) is recorded here. `caddy_reload` restores every
recorded file when validation fails, and discards the journal once Caddy
accepts the config.

Only the first write since the last accepted config records the previous
content, so the journal always holds what Caddy last validated. Each
entry also records what boxmunge wrote; a file that something else has
rewritten since (a pause or quarantine maintenance page) is left alone on
restore, so a restore never undoes another operation. Writers and the
restore both run under the global Caddy lock.

The journal is deploy-writable and root restores from it, so nothing in an
entry is trusted: it may only name the site file its own name names, in the
sites directory, neither of them a symlink, and must hold what write_site
writes. Anything else is refused with JournalError and never acted on.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from boxmunge.fileutil import atomic_write_text
from boxmunge.state import StateError

JOURNAL_DIRNAME = ".site-journal"
SITES_DIRNAME = "sites"
_ENTRY_SUFFIX = ".json"
# What paths.project_caddy_site and project_staging_caddy_site name.
_SITE_NAME = re.compile(r"[a-z0-9][a-z0-9-]*\.conf")
_RECORD_KEYS = frozenset({"path", "previous", "written"})

# Site files are read by the Caddy container through a bind mount whose
# uid may not map to the deploy user, so they stay world-readable. They
# hold routing config only, no secrets.
SITE_MODE = 0o644


class JournalError(StateError):
    """A journal entry or path boxmunge did not write: state it refuses, as
    any corrupt state file. `restored` names the site files restore_sites
    put back before refusing."""

    def __init__(self, message: str, restored: list[str] | None = None) -> None:
        super().__init__(message)
        self.restored = restored or []


def _real_dir(caddy_dir: Path, name: str) -> Path:
    """caddy_dir/name, refused if it is a symlink or not a directory."""
    path = caddy_dir / name
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise JournalError(
            f"{path} is a symlink or not a directory. boxmunge reads and "
            f"writes Caddy site files only in place; replace it with a "
            f"directory (as root) and redeploy."
        )
    return path


def _journal_dir(caddy_dir: Path) -> Path:
    return _real_dir(caddy_dir, JOURNAL_DIRNAME)


def _checked_site(caddy_dir: Path, name: str, what: str) -> Path:
    """The site file `name` in the sites directory, refused unless `name` is
    a site file name and the file, if present, is a regular file."""
    if not _SITE_NAME.fullmatch(name):
        raise JournalError(f"{what}: {name!r} is not a Caddy site file name.")
    site = _real_dir(caddy_dir, SITES_DIRNAME) / name
    if site.is_symlink() or (site.exists() and not site.is_file()):
        raise JournalError(
            f"{what}: {site} is a symlink or not a regular file. Delete it "
            f"(as root) and redeploy the project it belongs to."
        )
    return site


def _entry_site(caddy_dir: Path, site_path: Path) -> tuple[Path, Path]:
    """The checked site file boxmunge is about to write, and its entry."""
    if site_path.parent != caddy_dir / SITES_DIRNAME:
        raise JournalError(
            f"{site_path} is not in {caddy_dir / SITES_DIRNAME}; only site "
            f"files there are journaled."
        )
    site = _checked_site(caddy_dir, site_path.name, "site file")
    return site, _journal_dir(caddy_dir) / f"{site.name}{_ENTRY_SUFFIX}"


def _read_entry(caddy_dir: Path, entry: Path) -> tuple[Path, dict[str, Any]]:
    """The site file a journal entry restores, and its record. Raises
    JournalError, naming the entry, for anything write_site did not write."""
    def refuse(why: str) -> JournalError:
        return JournalError(
            f"{entry}: {why}. boxmunge did not write this journal entry and "
            f"will not restore from it. Delete it (as root) and check the site "
            f"files in {caddy_dir / SITES_DIRNAME}."
        )
    if entry.is_symlink() or not entry.is_file():
        raise refuse("is a symlink or not a regular file")
    try:
        site = _checked_site(caddy_dir, entry.name[:-len(_ENTRY_SUFFIX)], str(entry))
    except JournalError as e:
        raise refuse(str(e).removeprefix(f"{entry}: ")) from e
    try:
        record = json.loads(entry.read_text())
    except (OSError, ValueError, RecursionError) as e:
        raise refuse(f"is unreadable or not JSON ({e})") from e
    if not isinstance(record, dict) or record.keys() != _RECORD_KEYS:
        raise refuse(f"is not an object with exactly {sorted(_RECORD_KEYS)}")
    if record["path"] != str(site):
        raise refuse(f"names {record['path']!r}, not its own site file {site}")
    if not isinstance(record["written"], str) or not (
            record["previous"] is None or isinstance(record["previous"], str)):
        raise refuse("'written' must be text and 'previous' text or null")
    return site, record


def _read(path: Path) -> str | None:
    return path.read_text() if path.exists() else None


def write_site(caddy_dir: Path, site_path: Path, content: str) -> None:
    """Write a site file, journaling what it replaces if not yet journaled."""
    site, entry = _entry_site(caddy_dir, site_path)
    if entry.exists() or entry.is_symlink():
        previous = _read_entry(caddy_dir, entry)[1]["previous"]
    else:
        previous = _read(site)
    # atomic_write_text creates the journal directory (deploy-owned).
    atomic_write_text(entry, json.dumps(
        {"path": str(site), "previous": previous, "written": content},
    ))
    atomic_write_text(site, content, mode=SITE_MODE)


def remove_site(caddy_dir: Path, site_path: Path) -> None:
    """Delete a site file and forget any journal entry for it.

    For a site that is being torn down (unstage): a later restore must not
    bring back routing to containers that no longer exist. Removing a site
    cannot make Caddy's config invalid, so nothing needs journaling.
    """
    site, entry = _entry_site(caddy_dir, site_path)
    site.unlink(missing_ok=True)
    entry.unlink(missing_ok=True)


def restore_sites(caddy_dir: Path) -> list[str]:
    """Put every journaled site file back as Caddy last accepted it.

    Returns the restored file names. Files that did not exist before are
    removed. A file whose content is no longer what boxmunge journaled as
    written has been changed by another operation and is left as it is.
    Every valid entry is restored; then JournalError, naming each refused
    entry, is raised if there were any. A refused entry is left in place.
    """
    journal = _journal_dir(caddy_dir)
    if not journal.exists():
        return []
    restored: list[str] = []
    refused: list[str] = []
    for entry in sorted(journal.glob(f"*{_ENTRY_SUFFIX}")):
        try:
            site, record = _read_entry(caddy_dir, entry)
        except JournalError as e:
            refused.append(str(e))
            continue
        if _read(site) == record["written"]:
            if record["previous"] is None:
                site.unlink(missing_ok=True)
            else:
                atomic_write_text(site, record["previous"], mode=SITE_MODE)
            restored.append(site.name)
        entry.unlink()
    if refused:
        raise JournalError("\n".join(refused), restored)
    return restored


def commit_sites(caddy_dir: Path) -> None:
    """Forget the journal: Caddy has accepted the files now on disk."""
    journal = _journal_dir(caddy_dir)
    if not journal.exists():
        return
    for entry in journal.glob(f"*{_ENTRY_SUFFIX}"):
        entry.unlink()
