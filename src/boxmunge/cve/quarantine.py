# SPDX-License-Identifier: Apache-2.0
"""CVE-quarantine action primitives.

Quarantine takes a project offline in response to a policy decision
(QUARANTINE disposition). It is the policy-initiated counterpart to the
operator-initiated `pause` flow in boxmunge.pause: same shape of work
(swap Caddy site to maintenance, stop containers), distinct state file
(`<project>.quarantined.json`), distinct lifecycle (lifted only via
`boxmunge security resume`, not via `resume`).

Pause and quarantine are orthogonal — a project may be paused, quarantined,
both, or neither. They share the maintenance Caddyfile fragment renderer
(reused from boxmunge.pause) and the same compose+caddy primitives from
boxmunge.docker.

Order of operations matches pause: write state FIRST so any subsequent
failure leaves the project marked quarantined and a retry can converge;
swap Caddy BEFORE stopping containers so visitors never see "504 Bad
Gateway" between container stop and Caddy reload.

The record carries ``action_complete``: false until the maintenance page
is routed AND the containers are stopped with their restart policies set
to "no" (the originals are saved in the record and restored on lift). Every scan of a quarantined
project calls ``reassert_quarantine``, so a partially failed action is
retried until it completes (audit B-03) and drift (a container someone
started) is undone.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from boxmunge.cve.policy import FindingDisposition
from boxmunge import restart_hold
from boxmunge.docker import DockerError, caddy_reload, compose_stop, compose_up
from boxmunge.fileutil import atomic_write_text
from boxmunge.pause import hand_over_restart_policies, render_maintenance_caddy_config
from boxmunge.paths import BoxPaths

_LOGGER = logging.getLogger("boxmunge")


def _extra(
    project: str | None = None, detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Structured-extras helper for cve-quarantine events."""
    return {"component": "cve-quarantine", "project": project, "detail": detail}


class QuarantineError(Exception):
    """Quarantine action could not complete."""


# ---------- state primitives ----------


def is_quarantined(project_name: str, paths: BoxPaths) -> bool:
    """True if the project has been CVE-quarantined."""
    return paths.project_quarantine_state(project_name).exists()


def read_quarantine_state(
    project_name: str, paths: BoxPaths,
) -> dict[str, Any] | None:
    """Return the quarantine state dict, or None if not quarantined."""
    path = paths.project_quarantine_state(project_name)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise QuarantineError(
            f"Failed to read quarantine state for {project_name!r}: {e}",
        ) from e


def _write_record(project_name: str, paths: BoxPaths, data: dict[str, Any]) -> None:
    state_path = paths.project_quarantine_state(project_name)
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(state_path, json.dumps(data, indent=2) + "\n")
    except OSError as e:
        raise QuarantineError(
            f"Failed to write quarantine state for {project_name!r}: {e}",
        ) from e


def write_quarantine_state(
    project_name: str,
    paths: BoxPaths,
    *,
    headline: FindingDisposition,
    image_ref: str,
) -> dict[str, Any]:
    """Record quarantine state with ``action_complete: false``; return it.

    `headline` is the most-severe FindingDisposition that triggered the
    quarantine. Overwrites existing state with the new headline if called
    again; the action is then incomplete until re-asserted.
    """
    data: dict[str, Any] = {
        "quarantined_at": datetime.now(timezone.utc).isoformat(),
        "cve_id": headline.finding.cve_id,
        "severity": headline.base_severity.value,
        "effective_severity": headline.effective_severity.value,
        "explanation": headline.explanation,
        "image_ref": image_ref,
        "action_complete": False,
    }
    _write_record(project_name, paths, data)
    return data


def quarantine_action_complete(project_name: str, paths: BoxPaths) -> bool:
    """True iff the record says the maintenance page and stop both landed.

    A record without the field predates it and is treated as incomplete,
    so the next scan re-asserts it.
    """
    state = read_quarantine_state(project_name, paths)
    return bool(state and state.get("action_complete") is True)


def clear_quarantine_state(project_name: str, paths: BoxPaths) -> None:
    """Remove the quarantine state file. Idempotent (no-op if missing)."""
    paths.project_quarantine_state(project_name).unlink(missing_ok=True)


# ---------- compound actions ----------


def quarantine_project(
    project_name: str,
    paths: BoxPaths,
    *,
    project_dir: Path,
    hosts: list[str],
    compose_files: list[str],
    headline: FindingDisposition,
    image_ref: str,
) -> None:
    """Perform the full quarantine action.

    1. Write the quarantine record FIRST (``action_complete: false``) so any
       later failure leaves the project marked quarantined; the next scan
       re-asserts it (see ``reassert_quarantine``).
    2-4. ``reassert_quarantine``: maintenance page, Caddy reload, stop.

    On any step failure after step 1, raises QuarantineError but leaves
    the record in place — the project is quarantined-with-issues, never
    silently not-quarantined.
    """
    already = is_quarantined(project_name, paths)
    if already:
        _LOGGER.info(
            "quarantine: re-asserting on already-quarantined project %s "
            "(new headline %s)", project_name, headline.finding.cve_id,
            extra=_extra(
                project=project_name,
                detail={
                    "cve_id": headline.finding.cve_id,
                    "severity": headline.effective_severity.value,
                    "image_ref": image_ref,
                    "re_assert": True,
                },
            ),
        )
    else:
        _LOGGER.info(
            "quarantine: firing on %s (headline %s, image %s)",
            project_name, headline.finding.cve_id, image_ref,
            extra=_extra(
                project=project_name,
                detail={
                    "cve_id": headline.finding.cve_id,
                    "severity": headline.effective_severity.value,
                    "image_ref": image_ref,
                },
            ),
        )

    # 1. State file FIRST.
    state = write_quarantine_state(
        project_name, paths,
        headline=headline,
        image_ref=image_ref,
    )
    _complete_action(
        project_name, paths, state,
        project_dir=project_dir, hosts=hosts, compose_files=compose_files,
    )


def reassert_quarantine(
    project_name: str,
    paths: BoxPaths,
    *,
    project_dir: Path,
    hosts: list[str],
    compose_files: list[str],
) -> None:
    """Bring an existing quarantine record's action to completion.

    Order (matches pause flow — visitors should never see "504 Bad Gateway"):
    route the maintenance page, reload Caddy, then stop the containers.
    Idempotent and safe to call on every scan. Marks the record
    ``action_complete: true`` only once every step succeeded.
    """
    state = read_quarantine_state(project_name, paths)
    if state is None:
        raise QuarantineError(
            f"cannot re-assert quarantine for {project_name!r}: no record",
        )
    _complete_action(
        project_name, paths, state,
        project_dir=project_dir, hosts=hosts, compose_files=compose_files,
    )


def _complete_action(
    project_name: str,
    paths: BoxPaths,
    state: dict[str, Any],
    *,
    project_dir: Path,
    hosts: list[str],
    compose_files: list[str],
) -> None:
    """Steps 2-4 of the action, then mark the record complete."""
    # 2. Render maintenance Caddy site config and write atomically.
    try:
        site_conf = render_maintenance_caddy_config(hosts)
        atomic_write_text(
            paths.project_caddy_site(project_name), site_conf, mode=0o644,
        )
    except (OSError, ValueError) as e:
        raise QuarantineError(
            f"Failed to write maintenance Caddy config for "
            f"{project_name!r}: {e}",
        ) from e

    # 3. Reload Caddy so the maintenance page goes live.
    try:
        caddy_reload(paths.caddy, paths.state)
    except DockerError as e:
        raise QuarantineError(
            f"Failed to reload Caddy after writing maintenance config "
            f"for {project_name!r}: {e}",
        ) from e

    # 4. Stop containers (Caddy is already serving the maintenance page).
    try:
        compose_stop(project_dir, compose_files=compose_files,
                     project_name=project_name)
    except DockerError as e:
        raise QuarantineError(
            f"Failed to stop containers for {project_name!r}: {e}",
        ) from e

    # 5. Hold the stop across a Docker daemon restart or reboot (B-19).
    state = _pin_restart_policies(project_name, state)

    if state.get("action_complete") is not True:
        state = {**state, "action_complete": True}
    _write_record(project_name, paths, state)
    _LOGGER.info(
        "quarantine: %s offline behind maintenance page",
        project_name,
        extra=_extra(project=project_name),
    )


def _pin_restart_policies(project_name: str, state: dict[str, Any]) -> dict[str, Any]:
    """Hold the project's containers at restart policy "no" (B-19); return
    the record with each container's original policy saved for the lift."""
    try:
        saved = restart_hold.hold(project_name, state.get("restart_policies") or {})
    except DockerError as e:
        raise QuarantineError(
            f"Failed to disable restart policies for {project_name!r}: {e}",
        ) from e
    return {**state, "restart_policies": saved}


def _restore_restart_policies(project_name: str, state: dict[str, Any]) -> None:
    """Give each still-existing container its pre-quarantine policy back."""
    try:
        restart_hold.release(project_name, state.get("restart_policies") or {})
    except DockerError as e:
        raise QuarantineError(
            f"Failed to restore restart policies for {project_name!r}: {e}",
        ) from e


def lift_quarantine(
    project_name: str,
    paths: BoxPaths,
    *,
    project_dir: Path,
    project_caddy_site_content: str | None,
    compose_files: list[str],
) -> None:
    """Lift quarantine and restore normal serving.

    Steps:
    1. Atomic-write the regenerated normal site config to
       project_caddy_site.
    2. caddy_reload.
    3. Restore the saved restart policies, then compose_up WITHOUT a build,
       so the exact images the resume re-scan cleared come back (B-20).
    4. Clear the quarantine state file (LAST — only after restart succeeds).

    ``project_caddy_site_content=None`` lifts the quarantine but leaves the
    project down: the maintenance page stays and nothing starts. Used when
    the project is also paused — pause is lifted only by `resume` (B-20).

    The caller is responsible for regenerating the normal Caddyfile
    fragment (the resume command does this via existing helpers) and
    passing that rendered string as `project_caddy_site_content`. We
    don't reach into the manifest from here — keep this module
    compose+state focused.

    On any step failure, raises QuarantineError. State file is NOT
    cleared on failure — operator should retry once they've fixed the
    issue.

    Idempotent: if already not quarantined, no-op.
    """
    if not is_quarantined(project_name, paths):
        _LOGGER.info(
            "quarantine: lift requested for %s but not quarantined — no-op",
            project_name,
            extra=_extra(project=project_name),
        )
        return

    _LOGGER.info(
        "quarantine: lifting on %s", project_name,
        extra=_extra(project=project_name),
    )
    state = read_quarantine_state(project_name, paths) or {}

    if project_caddy_site_content is None:
        # Paused as well: keep the maintenance page, the stop and the held
        # restart policies; the pause record takes over the originals so
        # `resume` gives them back.
        hand_over_restart_policies(project_name, paths, state.get("restart_policies") or {})
        clear_quarantine_state(project_name, paths)
        _LOGGER.info(
            "quarantine: %s lifted; project stays paused", project_name,
            extra=_extra(project=project_name),
        )
        return

    # 1. Restore normal Caddy site config.
    try:
        atomic_write_text(
            paths.project_caddy_site(project_name),
            project_caddy_site_content,
            mode=0o644,
        )
    except OSError as e:
        raise QuarantineError(
            f"Failed to restore Caddy site for {project_name!r}: {e}",
        ) from e

    # 2. Reload Caddy so the restored config goes live.
    try:
        caddy_reload(paths.caddy, paths.state)
    except DockerError as e:
        raise QuarantineError(
            f"Failed to reload Caddy after restoring site config "
            f"for {project_name!r}: {e}",
        ) from e

    # 3. Restart containers, with their own restart policies back.
    _restore_restart_policies(project_name, state)
    try:
        compose_up(project_dir, compose_files=compose_files, build=False,
                   project_name=project_name)
    except DockerError as e:
        raise QuarantineError(
            f"Failed to restart containers for {project_name!r}: {e}",
        ) from e

    # 4. Only now clear state — surviving past compose_up means the
    #    project is genuinely back online.
    clear_quarantine_state(project_name, paths)
    _LOGGER.info(
        "quarantine: %s lifted, back online", project_name,
        extra=_extra(project=project_name),
    )
