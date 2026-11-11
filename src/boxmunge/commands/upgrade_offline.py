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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from boxmunge.compose import load_user_compose, prepare_compose_override, render_compose_override
from boxmunge.compose_guard import check_start
from boxmunge.cve.quarantine import QuarantineError, is_quarantined, read_quarantine_state
from boxmunge.fileutil import atomic_write_bytes
from boxmunge.fs_nofollow import open_regular_nofollow
from boxmunge.manifest import CURRENT_SCHEMA_VERSION
from boxmunge.pause import is_paused, read_paused_state
from boxmunge.paths import BoxPaths
from boxmunge.redeploy_hint import redeploy_or_bare
from boxmunge.state import StateError

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
    # deploying: nothing of the project starts here. Its existing containers
    # are checked by the start that brings it back (resume recreates ones
    # made before the own-file rules), which needs this record.
    try:
        check_start(paths, name, component="upgrade",
                    compose_files=["compose.yml", "compose.boxmunge.yml"], record=True,
                    regenerated=True, deploying=True)
    except Exception as e:  # noqa: BLE001 — a refusal (alerted by the check) or any other
        _put_back(kept)
        return f"its bind sources could not be recorded ({e}); {_STAYS}"
    return None


def in_memory_line(name: str, written: object) -> str:
    """The dry run's line for a git project whose repository manifest is
    migrated in memory (the checkout is not rewritten)."""
    if written is None:
        return (f"{name}: repository manifest.yml has no schema_version; the "
                f"upgrade will alert to set it to {CURRENT_SCHEMA_VERSION} in the "
                f"repository")
    return (f"{name}: repository manifest.yml uses schema v{written}; migrated in "
            f"memory to v{CURRENT_SCHEMA_VERSION} (the upgrade will alert to update "
            f"it in the repository)")


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


def offline_exit(paths: BoxPaths, name: str) -> str:
    """The ways back for a paused or quarantined project the upgrade
    refused, each with when it applies. Resume and `security resume` run
    the start checks, so they work once the project's files are back as
    deployed; a deploy takes them as they are. A deploy is refused while
    the project is paused, so `resume --no-start` hands the pause to it,
    and a quarantine lets it through, scanned, and lifts once it starts."""
    deploy = f"`boxmunge {redeploy_or_bare(paths, name)}`"
    back = "once the project's files are back as deployed"
    if not is_paused(name, paths):
        return (f"run `boxmunge security resume {name}` {back}, or {deploy} to deploy them "
                f"as they are (its images are scanned first; once it starts the quarantine "
                f"lifts)")
    from_pause = f"`boxmunge resume {name} --no-start`, then {deploy}"
    if not is_quarantined(name, paths):
        return f"run `boxmunge resume {name}` {back}, or {from_pause} to deploy them as they are"
    return (f"run {from_pause}: its images are scanned first, and once it starts the pause "
            f"ends and the quarantine lifts")


@dataclass(frozen=True)
class UnreadableRecord:
    """A project whose pause or quarantine record cannot be read (corrupt,
    or a link): the upgrade cannot tell whether it is meant to be offline,
    so it leaves it as it is and reports it (upgrade_exclusions)."""
    text: str

    def __str__(self) -> str:
        return self.text


def unreadable_record(paths: BoxPaths, name: str) -> UnreadableRecord | None:
    """Why the project's pause or quarantine record cannot be read, naming
    the file and the commands that work once it is removed, or None."""
    problems: list[str] = []
    ways: list[str] = []
    try:
        read_quarantine_state(name, paths)
    except QuarantineError as e:
        problems.append(f"its quarantine record cannot be read ({e})")
        ways.append(f"`boxmunge security scan {name}`, which quarantines it again if its "
                    f"images still call for it")
    try:
        read_paused_state(name, paths)
    except StateError as e:
        problems.append(f"its pause record cannot be read ({e})")
        # Its containers are stopped: a pause's snapshot has nothing to dump.
        ways.append(f"`boxmunge pause {name} --no-snapshot` to keep it paused")
    if not problems:
        return None
    it = "them" if len(problems) > 1 else "it"
    ways.append(f"`boxmunge {redeploy_or_bare(paths, name)}` to bring it back on this release")
    return UnreadableRecord(f"{'; '.join(problems)}. Inspect {it} and remove {it} as root, "
                            f"then run {', '.join(ways[:-1])}, or {ways[-1]}")
