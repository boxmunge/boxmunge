# SPDX-License-Identifier: Apache-2.0
"""A paused or quarantined project's overlay at a platform upgrade.

Such a project keeps its maintenance page and is not restarted, but its
overlay is regenerated and its bind sources recorded like a running
project's: resume and the quarantine lift start this release's overlay,
whose mounts may differ from the old one's (0.10.1 mounted the smoke
scripts from .releases/live-scripts), and check it against that record.
Nothing of the project runs, so a failure here is a refusal, alerted with
the upgrade's others, not a failed upgrade: the project keeps its previous
overlay and bind record, which still agree.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from boxmunge.compose import load_user_compose, prepare_compose_override, render_compose_override
from boxmunge.compose_guard import check_start
from boxmunge.fileutil import atomic_write_bytes
from boxmunge.fs_nofollow import open_regular_nofollow
from boxmunge.paths import BoxPaths

_STAYS = "it keeps its previous overlay and bind record and stays offline"


class PutBackError(Exception):
    """The previous overlay or bind record could not be put back, so the
    two may no longer agree."""


def render_overlay(paths: BoxPaths, name: str, manifest: dict[str, Any]) -> None:
    """The overlay the apply writes, rendered in memory (env files and users
    record included); nothing is written. Raises what the apply would."""
    render_compose_override(paths, manifest,
                            load_user_compose(paths.project_compose(name), name))


def _read(path: Path) -> bytes | None:
    """The file's bytes (None: absent), read without following a link: root
    must not copy whatever a planted link names into the project directory
    when it puts the file back. Raises OSError, also for a link or any other
    non-regular file."""
    try:
        fd = open_regular_nofollow(path, os.O_RDONLY)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as f:
        return f.read()


def _previous(paths: BoxPaths, name: str) -> dict[Path, bytes | None]:
    """The overlay and bind record as they are. Raises OSError (see _read)."""
    return {path: _read(path)
            for path in (paths.project_compose_override(name), paths.project_bind_record(name))}


def _unreadable(e: OSError) -> str:
    return (f"its overlay or bind record cannot be read safely ({e}); nothing was "
            f"changed and it stays offline")


def _unchanged(path: Path, content: bytes | None) -> bool:
    try:
        return _read(path) == content
    except OSError:
        return False


def _put_back(kept: dict[Path, bytes | None]) -> None:
    """Restore each file that changed; one that cannot be means the overlay
    and record may disagree (PutBackError)."""
    try:
        for path, content in kept.items():
            if _unchanged(path, content):
                continue
            if content is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write_bytes(path, content)
    except OSError as e:
        raise PutBackError(str(e)) from e


def regenerate_offline(paths: BoxPaths, name: str, manifest: dict[str, Any]) -> str | None:
    """Regenerate the overlay and record its bind sources (start checks
    included, as for a running project); return why the project is refused,
    or None. A failure after either file was written puts both back. Raises
    PutBackError when they cannot be."""
    try:
        kept = _previous(paths, name)
    except OSError as e:
        return _unreadable(e)
    try:
        prepare_compose_override(paths, manifest, component="upgrade")
    except Exception as e:  # noqa: BLE001 — every failure keeps the previous configs
        _put_back(kept)
        return f"its compose overlay could not be regenerated ({e}); {_STAYS}"
    try:
        check_start(paths, name, component="upgrade",
                    compose_files=["compose.yml", "compose.boxmunge.yml"], record=True)
    except Exception as e:  # noqa: BLE001 — a refusal (alerted by the check) or any other
        _put_back(kept)
        return f"its bind sources could not be recorded ({e}); {_STAYS}"
    return None


def offline_dry_run_line(paths: BoxPaths, name: str, manifest: dict[str, Any],
                         reason: str) -> str:
    """The dry run's line for the project: the refusal the apply would make,
    never a failed dry run. (The start checks the apply records through
    are not run: they write.)"""
    refused = f"{name}: {reason}; keeps its maintenance page; would be refused:"
    try:
        _previous(paths, name)
    except OSError as e:
        return f"{refused} {_unreadable(e)}"
    try:
        render_overlay(paths, name, manifest)
    except Exception as e:  # noqa: BLE001 — the apply refuses on any failure
        return f"{refused} its compose overlay could not be regenerated ({e})"
    return f"{name}: {reason}; keeps its maintenance page, overlay renders OK"
