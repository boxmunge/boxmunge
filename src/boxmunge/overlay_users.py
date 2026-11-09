# SPDX-License-Identifier: Apache-2.0
"""Whether production's overlay runs each service as the users record says.

The overlay (compose.boxmunge.yml) replays the users record only when it is
rendered (compose.prepare_compose_override). A start that runs the overlay
as it is after the record changed (`data chown` writes it) would start a
service as its old user over data its new one owns. Every production start
that does not render the overlay itself is checked against the record
first (compose_guard.check_start). A `docker start` runs a container as it
was created, so the containers it would start are checked the same way
(compose_guard.check_containers_start).
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from boxmunge.fs_nofollow import read_text_nofollow
from boxmunge.run_as import RunAsError, read_users

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


class StaleOverlay(Exception):
    """The overlay or the record cannot be read, or they disagree."""


def _overlay_users(overlay: Path) -> dict[str, object]:
    try:
        doc = yaml.safe_load(read_text_nofollow(overlay))
    except (OSError, yaml.YAMLError) as e:
        raise StaleOverlay(f"cannot read {overlay}: {e}") from e
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, dict):
        raise StaleOverlay(f"{overlay} has no services")
    return {name: svc.get("user") for name, svc in services.items() if isinstance(svc, dict)}


def _record(paths: BoxPaths, project: str) -> dict[str, str | None]:
    """{service: the user its overlay emits} from the record. Raises
    StaleOverlay for a record that cannot be read."""
    try:
        return {name: user.emitted() for name, user in read_users(paths, project).items()}
    except RunAsError as e:
        raise StaleOverlay(str(e)) from e


def stale_containers_problem(paths: BoxPaths, project: str,
                             created: dict[str, str]) -> str | None:
    """Why `docker start` of the containers (`created`: {service: the User
    it was created with}) would not run a recorded service as the record
    says, or None. Only a user boxmunge sets is compared: one the image or
    compose.yml sets is in the container's config whatever the record says."""
    try:
        record = _record(paths, project)
    except StaleOverlay as e:
        return str(e)
    wrong = [f"{name} (created as {created[name] or 'its image user'}, the record says "
             f"{record[name]})"
             for name in sorted(record) if name in created
             and record[name] is not None and created[name] != record[name]]
    if not wrong:
        return None
    return (f"its stopped containers of {', '.join(wrong)} were created before the users "
            f"record changed (data chown writes it), so starting them would run the old "
            f"user over data the new one owns. Run `prod-deploy {project}`, which "
            f"recreates them")


def stale_overlay_problem(paths: BoxPaths, project: str) -> str | None:
    """Why production's overlay would not run every recorded service as the
    record says, or None. A service the overlay does not name is not this
    release's, and is not compared."""
    try:
        record = _record(paths, project)
    except StaleOverlay as e:
        return str(e)
    if not record:
        return None
    overlay = paths.project_compose_override(project)
    try:
        in_overlay = _overlay_users(overlay)
    except StaleOverlay as e:
        return str(e)
    wrong = [f"{name} (the record says {user or 'its image user'}, the overlay "
             f"{in_overlay[name] or 'its image user'})"
             for name, user in sorted(record.items())
             if name in in_overlay and in_overlay[name] != user]
    if not wrong:
        return None
    return (f"{overlay.name} does not run {', '.join(wrong)}: the users record changed "
            f"after it was generated (data chown writes the record), so a start would "
            f"run the old user over data the new one owns. Run `prod-deploy {project}`, "
            f"which generates it again (`resume {project}`, `recover {project}` or "
            f"`security resume {project}` when it is paused, stopped by the health "
            f"monitor or CVE-quarantined)")
