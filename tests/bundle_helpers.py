"""Shared helpers for tests that drive bundle intake end to end.

They build real tar.gz bundles in the inbox and snapshot real project trees,
so the deploy/stage/rollback tests exercise filesystem behaviour rather than
mocks of the code under test.
"""
from __future__ import annotations

import tarfile
from pathlib import Path

from boxmunge.paths import BoxPaths

ULID = "01TESTULID0000000000000000"


def manifest_text(project: str = "myapp", ulid: str = ULID, backup: str = "none") -> str:
    return (
        f"id: {ulid}\n"
        f"project: {project}\n"
        "source: bundle\n"
        "hosts:\n"
        f"  - {project}.example.com\n"
        "services:\n"
        "  web:\n"
        "    port: 8080\n"
        "    routes:\n"
        "      - path: /\n"
        "backup:\n"
        f"  type: {backup}\n"
        + ("" if backup == "none" else
           "  dump_command: dump.sh\n  restore_command: restore.sh\n")
    )


SAFE_COMPOSE = "services:\n  web:\n    image: nginx\n"
HOSTILE_COMPOSE = "services:\n  web:\n    image: nginx\n    privileged: true\n"


def place_bundle(
    paths: BoxPaths,
    project: str = "myapp",
    timestamp: str = "2026-10-13T100000000000",
    files: dict[str, str] | None = None,
) -> Path:
    """Write a bundle `<project>-<timestamp>.tar.gz` into the inbox.

    `files` maps relative paths to contents; manifest.yml and compose.yml
    default to a valid manifest and a safe compose file.
    """
    contents = {"manifest.yml": manifest_text(project), "compose.yml": SAFE_COMPOSE}
    contents.update(files or {})
    src = paths.root / "bundle-src" / f"{project}-{timestamp}" / project
    for rel, text in contents.items():
        target = src / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    paths.inbox.mkdir(parents=True, exist_ok=True)
    bundle = paths.inbox / f"{project}-{timestamp}.tar.gz"
    with tarfile.open(bundle, "w:gz") as tar:
        tar.add(src, arcname=project)
    return bundle


def tree_snapshot(root: Path) -> dict[str, bytes | str]:
    """Every path under root mapped to its bytes (files) or a marker (dirs/links)."""
    snap: dict[str, bytes | str] = {}
    if not root.exists():
        return snap
    for p in sorted(root.rglob("*")):
        rel = str(p.relative_to(root))
        if p.is_symlink():
            snap[rel] = f"link:{p.readlink()}"
        elif p.is_dir():
            snap[rel] = "dir"
        else:
            snap[rel] = p.read_bytes()
    return snap
