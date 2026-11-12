"""Shared by the backup alert, sync alert and backup-freshness tests."""
from __future__ import annotations

from pathlib import Path

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
