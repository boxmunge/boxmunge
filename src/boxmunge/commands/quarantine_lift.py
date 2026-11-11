# SPDX-License-Identifier: Apache-2.0
"""Lifting a CVE quarantine and bringing the project back.

Shared by `boxmunge security resume` and by the scan that clears a
`balanced` project's quarantine (it lifts on its own then:
security_enforce.clears_quarantine). Both have scanned every image the lift
will start, and hold the project lock.

Whether a lift may start the project is decided here, for both (start_hold):
a project that is also paused, or that the health monitor stopped, has its
quarantine lifted but stays down. The pause is the operator's own decision
(B-20), lifted only by `boxmunge resume`; the monitor's stop stands until
`boxmunge recover`, and the monitor and container-update skip the project
while it does, so a started one would run unwatched.
"""
from __future__ import annotations

from dataclasses import dataclass

from boxmunge.bind_sources import BindSourceError
from boxmunge.caddy import prepare_caddy_config
from boxmunge.commands.health_state import is_monitor_stopped
from boxmunge.compose import prepare_compose_override
from boxmunge.compose_guard import ComposeRefused, check_start
from boxmunge.cve.quarantine import (
    QuarantineError, lift_quarantine, mark_quarantine_incomplete, reassert_quarantine,
)
from boxmunge.docker_run import DockerError
from boxmunge.health_checks.smoke import run_smoke
from boxmunge.manifest import ManifestError, load_manifest
from boxmunge.pause import is_paused
from boxmunge.paths import BoxPaths


@dataclass(frozen=True)
class Restored:
    """What the lift left running."""

    # Why the project stays down (start_hold), naming the command that brings
    # it back; None when it was started.
    held: str | None = None
    # (passed, message) of the smoke test; None when held.
    smoke: tuple[bool, str] | None = None


def start_hold(paths: BoxPaths, project: str) -> str | None:
    """Why a quarantine lift must leave ``project`` down, naming what brings
    it back, or None when the lift may start it. The one rule for every
    lift: the scan's and `security resume`."""
    if is_paused(project, paths):
        return f"it is paused; `boxmunge resume {project}` brings it back"
    if is_monitor_stopped(project, paths):
        return (f"the health monitor stopped it; `boxmunge recover {project}` brings "
                f"it back")
    return None


def compose_files_for(paths: BoxPaths, project: str) -> list[str]:
    compose_files = ["compose.yml"]
    if paths.project_compose_override(project).exists():
        compose_files.append("compose.boxmunge.yml")
    return compose_files


def restore_from_quarantine(paths: BoxPaths, project: str, *, component: str) -> Restored:
    """Lift ``project``'s quarantine and start it again. Caller holds the
    project lock and has scanned what will start.

    Raises QuarantineError, the record kept, when the lift cannot complete.
    The overlay is regenerated first, so the start checks see the overlay
    `compose up` will run, and a refused start is refused before the live
    Caddy config is rewritten. A failure once it is (a render, the reload,
    `compose up`) re-asserts the quarantine before raising, so visitors get
    the maintenance page back, not a 502 until the next scan.
    """
    held = start_hold(paths, project)
    if held is not None:
        lift_quarantine(project, paths, project_caddy_site_content=None,
                        compose_files=[], component=component)
        return Restored(held=held)
    try:
        manifest = load_manifest(paths.project_manifest(project))
    except ManifestError as e:
        raise QuarantineError(str(e)) from e
    try:
        prepare_compose_override(paths, manifest, component=component)
    except (OSError, ValueError, DockerError, BindSourceError) as e:
        raise QuarantineError(f"Failed to regenerate the compose overlay: {e}") from e
    try:
        check_start(paths, project, component=component,
                    compose_files=compose_files_for(paths, project))
    except ComposeRefused as e:
        raise QuarantineError(str(e)) from e
    try:
        _start(paths, project, manifest, component)
    except QuarantineError as e:
        _put_back(paths, project, manifest, e)
    return Restored(smoke=run_smoke(project, paths))


def _start(paths: BoxPaths, project: str, manifest: dict, component: str) -> None:
    try:
        site_content = prepare_caddy_config(paths, manifest)
    except (OSError, ValueError) as e:
        raise QuarantineError(f"Failed to render Caddy: {e}") from e
    lift_quarantine(project, paths, project_caddy_site_content=site_content,
                    compose_files=compose_files_for(paths, project), component=component)


def _put_back(paths: BoxPaths, project: str, manifest: dict, error: QuarantineError) -> None:
    """Re-assert the quarantine a failed lift left half undone; always raises."""
    try:
        reassert_quarantine(project, paths, project_dir=paths.project_dir(project),
                            hosts=list(manifest.get("hosts") or []),
                            compose_files=compose_files_for(paths, project))
    except QuarantineError as e:
        try:
            mark_quarantine_incomplete(project, paths)
        except QuarantineError as mark_error:
            e = QuarantineError(f"{e}; marking the record incomplete failed too: {mark_error}")
        raise QuarantineError(f"{error}; putting the maintenance page back failed too: "
                              f"{e}") from error
    raise QuarantineError(f"{error}. The quarantine stays: the maintenance page is back "
                          f"and the containers are stopped.") from error
