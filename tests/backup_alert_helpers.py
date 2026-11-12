"""Shared by the backup alert, sync alert and backup-freshness tests."""
from __future__ import annotations

import errno
from datetime import datetime
from pathlib import Path

from boxmunge.backup_evidence import record_snapshot
from boxmunge.paths import BoxPaths

MANIFEST = """\
project: {name}
repo: ""
ref: main
hosts:
  - {name}.example.com
services:
  web:
    type: frontend
    port: 3000
    routes:
      - path: /
backup:
  type: {backup}
  dump_command: "boxmunge-scripts/backup.sh"
  restore_command: "boxmunge-scripts/restore.sh"
  retention: 3
env_files: []
"""
CONFIG = "hostname: box.example.com\nadmin_email: a@example.com\n"
REMOTE = "backup_remote: offsite:bucket\n"


def snapshot_name(project: str, stamp: str) -> str:
    return f"{project}-{stamp}-ab12cd34-nightly.tar.gz.age"


def backed_up_project(paths: BoxPaths, name: str, backup: str = "db-dump") -> Path:
    """A deployed project with a backup configured, and the box's backup key."""
    pdir = paths.project_dir(name)
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(MANIFEST.format(name=name, backup=backup))
    (pdir / "backups").mkdir()
    paths.backup_key.parent.mkdir(parents=True, exist_ok=True)
    paths.backup_key.write_text("# public key: age1test\nAGE-SECRET-KEY-1TEST\n")
    return pdir


def stored_snapshot(paths: BoxPaths, project: str, at: datetime) -> str:
    """A snapshot on disk named for `at`, as an earlier backup left it."""
    name = snapshot_name(project, at.strftime("%Y-%m-%dT%H%M%S"))
    (paths.project_backups(project) / name).write_bytes(b"sealed")
    return name


def backed_up_at(paths: BoxPaths, project: str, at: datetime) -> str:
    """What a good backup at `at` leaves: the snapshot on disk, and its record."""
    name = stored_snapshot(paths, project, at)
    record_snapshot(paths, project, name, now=at)
    return name


def no_space(*a, **k):
    """Stands in for backup_evidence.write_state on a full disk."""
    raise OSError(errno.ENOSPC, "No space left on device")


class Alerts:
    """Stands in for notify: records each alert; delivers unless told not to."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str, int]] = []
        self.delivers = True

    def __call__(self, paths, title, body, *, component, project=None, priority=0) -> bool:
        assert component == "backup"
        self.sent.append((title, body, priority))
        return self.delivers

    @property
    def titles(self) -> list[tuple[str, int]]:
        return [(title, priority) for title, _body, priority in self.sent]
