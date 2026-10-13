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
"""
from __future__ import annotations

import json
from pathlib import Path

from boxmunge.fileutil import atomic_write_text

JOURNAL_DIRNAME = ".site-journal"

# Site files are read by the Caddy container through a bind mount whose
# uid may not map to the deploy user, so they stay world-readable. They
# hold routing config only, no secrets.
SITE_MODE = 0o644


def _journal_dir(caddy_dir: Path) -> Path:
    return caddy_dir / JOURNAL_DIRNAME


def _read(path: Path) -> str | None:
    return path.read_text() if path.exists() else None


def write_site(caddy_dir: Path, site_path: Path, content: str) -> None:
    """Write a site file, journaling what it replaces if not yet journaled."""
    entry = _journal_dir(caddy_dir) / f"{site_path.name}.json"
    if entry.exists():
        previous = json.loads(entry.read_text())["previous"]
    else:
        previous = _read(site_path)
    # atomic_write_text creates the journal directory (deploy-owned).
    atomic_write_text(entry, json.dumps(
        {"path": str(site_path), "previous": previous, "written": content},
    ))
    atomic_write_text(site_path, content, mode=SITE_MODE)


def restore_sites(caddy_dir: Path) -> list[str]:
    """Put every journaled site file back as Caddy last accepted it.

    Returns the restored file names. Files that did not exist before are
    removed. A file whose content is no longer what boxmunge journaled as
    written has been changed by another operation and is left as it is.
    """
    journal = _journal_dir(caddy_dir)
    if not journal.exists():
        return []
    restored: list[str] = []
    for entry in sorted(journal.glob("*.json")):
        record = json.loads(entry.read_text())
        site_path = Path(record["path"])
        if _read(site_path) == record["written"]:
            if record["previous"] is None:
                site_path.unlink(missing_ok=True)
            else:
                atomic_write_text(site_path, record["previous"], mode=SITE_MODE)
            restored.append(site_path.name)
        entry.unlink()
    return restored


def commit_sites(caddy_dir: Path) -> None:
    """Forget the journal: Caddy has accepted the files now on disk."""
    journal = _journal_dir(caddy_dir)
    if not journal.exists():
        return
    for entry in journal.glob("*.json"):
        entry.unlink()
