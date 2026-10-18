# SPDX-License-Identifier: Apache-2.0
"""boxmunge pause <project> — take a project offline with a maintenance page."""
from __future__ import annotations

import sys

from boxmunge.docker import compose_stop, caddy_reload, DockerError
from boxmunge.fileutil import LockError, atomic_write_text, project_lock
from boxmunge.legacy_stage import refuse_if_legacy_stage
from boxmunge.log import log_error, log_operation, log_warning
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.lifecycle import migration_refusal
from boxmunge.pause import (
    hold_restart_policies, is_paused, mark_pause_complete, pause_action_complete,
    render_maintenance_caddy_config, write_paused_state,
)
from boxmunge.paths import BoxPaths
from boxmunge.staged_release import SlotError, clear_production_stopped


def run_pause(
    project_name: str,
    paths: BoxPaths,
    yes: bool = False,
    reason: str | None = None,
) -> int:
    """pause: confirm, take the project lock and pause. Returns 0 on
    success, 1 on failure.

    Checks and the confirmation prompt run first; the pause itself runs
    under the project lock so it cannot interleave with a deploy, restore,
    scan, or health tick.
    """
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists() or not (project_dir / "manifest.yml").exists():
        print(f"ERROR: Project not found: {project_name}", file=sys.stderr)
        return 1

    if _refuse_if_already_paused(project_name, paths):
        return 1

    hosts = _manifest_hosts(project_name, paths)
    if hosts is None:
        return 1

    if not yes:
        print(f"This will pause '{project_name}':")
        print(f"  - Visitors to {', '.join(hosts)} see a maintenance page")
        print(f"  - Containers stopped (state preserved)")
        print(f"  - Health checks, backups, container-updates skip this project")
        response = input("\nProceed? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            return 1

    try:
        with project_lock(project_name, paths):
            return pause_locked(project_name, paths, reason)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def _refuse_if_already_paused(project_name: str, paths: BoxPaths) -> bool:
    """A completed pause refuses; an incomplete one is finished by pausing
    again."""
    if is_paused(project_name, paths) and pause_action_complete(project_name, paths):
        print(f"ERROR: Project '{project_name}' is already paused.",
              file=sys.stderr)
        return True
    return False


def _manifest_hosts(project_name: str, paths: BoxPaths) -> list[str] | None:
    """The manifest's hosts, or None (after printing why) if unusable."""
    try:
        manifest = load_manifest(paths.project_manifest(project_name))
    except ManifestError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return None
    hosts = manifest.get("hosts", [])
    if not hosts:
        print(f"ERROR: Project '{project_name}' has no hosts in manifest.",
              file=sys.stderr)
        return None
    return hosts


def pause_locked(project_name: str, paths: BoxPaths, reason: str | None) -> int:
    """The pause core. Caller holds the project lock; never takes it.

    The pause record is written first, marked incomplete, so automation
    (health checks, backups, updates, upgrade restarts) leaves the project
    alone from the start. It is marked complete only once the maintenance
    page is live, the containers are stopped and their restart policies
    held. If a step fails the record stays incomplete and says so, and
    running pause again finishes it.
    """
    refusal = migration_refusal(f"Pausing '{project_name}'", paths)
    if refusal:
        print(f"ERROR: {refusal}", file=sys.stderr)
        return 1
    if refuse_if_legacy_stage(paths, project_name):
        return 1
    # Re-check under the lock: a pause may have landed while the operator
    # was answering the prompt.
    if _refuse_if_already_paused(project_name, paths):
        return 1
    hosts = _manifest_hosts(project_name, paths)
    if hosts is None:
        return 1

    if is_paused(project_name, paths):
        print(f"Finishing the incomplete pause of '{project_name}'...")
    else:
        write_paused_state(project_name, paths, reason=reason)

    # Swap Caddy site config BEFORE stopping containers — visitors should
    # never see "504 Bad Gateway" between container stop and config swap.
    try:
        site_conf = render_maintenance_caddy_config(hosts)
        atomic_write_text(paths.project_caddy_site(project_name),
                          site_conf, mode=0o644)
        caddy_reload(paths.caddy, paths.state)
    except (DockerError, OSError) as e:
        return _pause_incomplete(
            project_name, paths, f"swapping in the maintenance page failed: {e}")

    project_dir = paths.project_dir(project_name)
    compose_files = ["compose.yml"]
    if paths.project_compose_override(project_name).exists():
        compose_files.append("compose.boxmunge.yml")
    try:
        compose_stop(project_dir, compose_files=compose_files,
                     project_name=project_name)
    except DockerError as e:
        return _pause_incomplete(
            project_name, paths, f"stopping the containers failed: {e}")
    _take_over_copy_stop(project_name, paths)
    # Keep it stopped across a Docker restart or reboot (B-19 for pause).
    try:
        hold_restart_policies(project_name, paths)
    except DockerError as e:
        return _pause_incomplete(
            project_name, paths, f"its restart policies could not be disabled: "
            f"{e}; a Docker restart may start `restart: always` services")
    mark_pause_complete(project_name, paths)

    log_operation("pause", "Project paused", paths,
                  project=project_name,
                  detail={"reason": reason} if reason else None)
    print(f"Project '{project_name}' paused.")
    print(f"  Visitors to {', '.join(hosts)} see the maintenance page.")
    print(f"  Run 'resume {project_name}' to bring back online.")
    return 0


def _take_over_copy_stop(project_name: str, paths: BoxPaths) -> None:
    """The stop is pause's now: a staging copy's production_stopped marker
    no longer stands (resume starts production). A slot that cannot be
    read or written is said, not raised: the pause itself succeeded."""
    try:
        clear_production_stopped(paths, project_name)
    except (SlotError, OSError) as e:
        message = (f"{project_name}'s staged slot could not be read or written to clear "
                   f"staging's production_stopped marker: {e}. Inspect the slot and "
                   f"unstage {project_name}")
        print(f"  WARN: {message}.", file=sys.stderr)
        log_warning("pause", message, paths, project=project_name)


def _pause_incomplete(project_name: str, paths: BoxPaths, what: str) -> int:
    print(f"ERROR: Pausing '{project_name}' is incomplete: {what}.\n"
          f"       It is marked paused, so health checks, backups and updates "
          f"skip it, but it may still be serving or running. Fix the cause "
          f"and run 'pause {project_name}' again to finish, or 'resume "
          f"{project_name}' to bring it back.", file=sys.stderr)
    log_error("pause", f"Pause incomplete: {what}", paths, project=project_name)
    return 1


def cmd_pause(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name
    parsed = parse_args(
        "pause", args, flags={"--yes"}, options={"--reason"},
        min_positional=1, max_positional=1,
    )
    project = require_project_name("pause", parsed.positional[0])
    yes = parsed.has("--yes")
    reason = parsed.get("--reason")

    paths = BoxPaths()
    sys.exit(run_pause(project, paths, yes=yes, reason=reason))
