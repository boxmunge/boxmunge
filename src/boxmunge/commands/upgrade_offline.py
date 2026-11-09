# SPDX-License-Identifier: Apache-2.0
"""A paused or quarantined project's overlay at a platform upgrade.

Such a project keeps its maintenance page and is not restarted, but its
overlay is regenerated and its bind sources recorded like a running
project's: resume and the quarantine lift start this release's overlay,
whose mounts may differ from the old one's (0.10.1 mounted the smoke
scripts from .releases/live-scripts), and check it against that record.
Nothing of the project runs, so an overlay that cannot be regenerated is a
refusal, alerted with the upgrade's others, not a failed upgrade.
"""
from __future__ import annotations

from typing import Any

from boxmunge.compose import load_user_compose, prepare_compose_override, render_compose_override
from boxmunge.fileutil import atomic_write_bytes
from boxmunge.paths import BoxPaths


def render_overlay(paths: BoxPaths, name: str, manifest: dict[str, Any]) -> None:
    """The overlay the apply writes, rendered in memory (env files and users
    record included); nothing is written. Raises what the apply would."""
    render_compose_override(paths, manifest,
                            load_user_compose(paths.project_compose(name), name))


def regenerate_offline_overlay(paths: BoxPaths, name: str,
                               manifest: dict[str, Any]) -> str | None:
    """Regenerate the overlay; return why it could not be, or None. On a
    failure the previous overlay and bind record are put back, so the two
    still agree. Raises OSError when they cannot be read or put back."""
    kept = {path: path.read_bytes() if path.exists() else None
            for path in (paths.project_compose_override(name), paths.project_bind_record(name))}
    try:
        prepare_compose_override(paths, manifest, component="upgrade")
    except Exception as e:  # noqa: BLE001 — every failure keeps the previous configs
        for path, content in kept.items():
            if content is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write_bytes(path, content)
        return (f"its compose overlay could not be regenerated ({e}); it keeps its "
                f"previous overlay and stays offline")
    return None


def offline_dry_run_line(paths: BoxPaths, name: str, manifest: dict[str, Any],
                         reason: str) -> str:
    """The dry run's line for the project: the apply's refusal, never a
    failed dry run, when its overlay does not render."""
    try:
        render_overlay(paths, name, manifest)
    except Exception as e:  # noqa: BLE001 — the apply refuses on any failure
        return (f"{name}: {reason}; keeps its maintenance page; would be refused: its "
                f"compose overlay could not be regenerated ({e}), so it would keep its "
                f"previous overlay and stay offline")
    return f"{name}: {reason}; keeps its maintenance page, overlay renders OK"
