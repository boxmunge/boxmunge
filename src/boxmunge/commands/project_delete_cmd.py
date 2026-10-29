# SPDX-License-Identifier: Apache-2.0
"""boxmunge project-delete <project> — destructive removal: containers, files, registry.

Containers (production and staging) are torn down first. If that fails,
nothing is deleted: the compose files are what a retry needs to reach the
containers. ``--force`` deletes anyway and warns that containers may be
left running. On success every per-project file goes, including pause and
quarantine markers, so a project later created with the same name starts
clean.
"""

import os
import shutil
import sys
from pathlib import Path

from boxmunge.built_images import remove_built_images
from boxmunge import docker_containers
from boxmunge.data_helper import container_owned_dirs, empty_under
from boxmunge.docker import DockerError, caddy_reload, compose_down, staging_compose_project
from boxmunge.fileutil import LockError, project_lock
from boxmunge.legacy_stage import legacy_staging_compose, legacy_staging_state
from boxmunge.lifecycle import migration_refusal
from boxmunge.log import log_error, log_operation, log_warning
from boxmunge.paths import BoxPaths
from boxmunge.project_alerts import ALERT_KINDS, alert_state
from boxmunge.project_registry import is_registered, remove_project as registry_remove
from boxmunge.staged_release import has_slot, refuse_planted, staging_target


def project_state_files(paths: BoxPaths, name: str) -> list[Path]:
    """Every per-project file kept outside the project directory.

    The project lock file (``state/<name>.lock``) is deliberately absent:
    project-delete holds that lock, and unlinking a lock file in use would
    let a new opener lock a fresh inode alongside the current holder.
    """
    return [
        paths.project_health_state(name),
        paths.project_deploy_state(name),
        paths.project_bind_record(name),
        paths.project_bind_record(name, staging=True),
        paths.project_users_record(name),
        paths.project_users_record(name, staging=True),
        paths.project_user_drift(name),
        paths.project_paused_state(name),
        paths.project_quarantine_state(name),
        paths.project_scan_state(name),
        legacy_staging_state(paths, name),
        paths.container_update_target_state(name),
        *(alert_state(paths, name, kind) for kind in ALERT_KINDS),
    ]


def remove_project_state(paths: BoxPaths, name: str) -> None:
    """Delete the per-project files kept outside the project directory."""
    for state_file in project_state_files(paths, name):
        state_file.unlink(missing_ok=True)
    alerts_dir = paths.project_alerts_dir(name)
    if alerts_dir.is_dir():
        alerts_dir.rmdir()  # fails loudly on a record kind ALERT_KINDS lacks


def run_project_delete(
    project_name: str, paths: BoxPaths, yes: bool = False, force: bool = False,
) -> int:
    """Delete a project: stop containers, remove Caddy config, delete files, deregister."""
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists() and not is_registered(project_name, paths):
        print(f"ERROR: Project not found: {project_name}", file=sys.stderr)
        return 1

    if not yes:
        print(f"This will permanently delete project '{project_name}':")
        print("  - Stop and remove all containers (production and staging)")
        print(f"  - Delete {project_dir}, including its local backups")
        print("    (off-site copies made by backup-sync are kept; backup-sync never deletes)")
        print("  - Remove Caddy site config")
        print("  - Remove health, deploy, pause, quarantine, scan, and update state")
        print("  - Deregister from project allowlist")
        response = input("\nProceed? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            return 1

    try:
        with project_lock(project_name, paths):
            return delete_locked(project_name, paths, force)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def _teardown(project_name: str, paths: BoxPaths) -> list[str]:
    """compose down production and staging, and remove the images built for
    them. Returns the failures."""
    project_dir = paths.project_dir(project_name)
    failures: list[str] = []
    if paths.project_compose(project_name).exists():
        compose_files = ["compose.yml"]
        if paths.project_compose_override(project_name).exists():
            compose_files.append("compose.boxmunge.yml")
        try:
            compose_down(project_dir, compose_files=compose_files,
                         project_name=project_name, remove_orphans=True)
        except DockerError as e:
            failures.append(f"production: {e}")
    try:
        _staging_down(project_name, paths)
    except (DockerError, OSError) as e:
        failures.append(f"staging: {e}")
    # Only the images the platform built for this project: their names
    # (boxmunge.invalid/<compose-project>/...) belong to no one else.
    for compose_project in (project_name, f"{project_name}-staging"):
        try:
            remove_built_images(compose_project)
        except DockerError as e:
            failures.append(f"built images of {compose_project}: {e}")
    return failures


def _staging_down(project_name: str, paths: BoxPaths) -> None:
    """compose down staging, from the slot (a link planted in its place is
    refused, never followed), or from the project dir for a stage left by
    boxmunge 0.10.1. Raises DockerError or OSError."""
    if has_slot(paths, project_name):
        refuse_planted(paths, project_name)
        target = staging_target(paths, project_name)
        compose_down(target.cwd, remove_orphans=True, **target.kwargs())
        return
    project_dir = paths.project_dir(project_name)
    legacy = legacy_staging_compose(project_dir)
    if legacy is not None:
        compose_down(project_dir, compose_files=legacy,
                     project_name=staging_compose_project(project_name), remove_orphans=True)


class ContainersLeft(Exception):
    """Containers of the project still exist, so its data may still change."""


def _containers_left(project_name: str) -> list[str]:
    """Every container labelled for the project or its staging, whatever
    the compose files on disk say: `compose down` leaves `compose run`
    one-offs, and a retry after a forced delete has no files to go down."""
    return [c.name for p in (project_name, f"{project_name}-staging")
            for c in docker_containers.project_containers(p)]


def _remove_project_dir(project_name: str, project_dir: Path) -> None:
    """Containers' data belongs to their users (S+N on a remapped box); the
    helper empties it so the rest can be removed as deploy. The helper
    mounts only the project directory, which no container can write, so a
    link a container planted in its data leads nowhere outside the project
    (data_helper.empty_under); and it is not used at all while any of the
    project's containers exists to plant one."""
    owned = container_owned_dirs(project_dir)
    if owned:
        left = _containers_left(project_name)
        if left:
            raise ContainersLeft(
                f"containers of '{project_name}' still exist ({', '.join(left)}) and could "
                f"change its data while it is removed. Remove them (docker rm -f "
                f"{' '.join(left)})")
        for path in owned:
            empty_under(f"{project_name}-delete", project_dir, path.relative_to(project_dir))
            # Still the container user's, and often 0700: deploy cannot list
            # it, which rmtree would, but may remove it from its own parent.
            os.rmdir(path)
    shutil.rmtree(project_dir)


def delete_locked(project_name: str, paths: BoxPaths, force: bool) -> int:
    """Tear down and remove the project. Caller holds the project lock."""
    refusal = migration_refusal(f"Deleting '{project_name}'", paths)
    if refusal:
        print(f"ERROR: {refusal}", file=sys.stderr)
        return 1
    failures = _teardown(project_name, paths)
    if failures:
        detail = "; ".join(failures)
        if not force:
            print(f"ERROR: Could not remove the containers of '{project_name}': {detail}",
                  file=sys.stderr)
            print("  Nothing was deleted; the compose files are kept so you can retry.\n"
                  "  Fix the cause and run project-delete again, or pass --force to "
                  "delete anyway (containers may be left running).", file=sys.stderr)
            log_error("project-delete", f"Teardown failed, nothing deleted: {detail}",
                      paths, project=project_name)
            return 1
        print(f"  WARN: --force: deleting despite teardown failure ({detail}). "
              f"Containers named '{project_name}-*' may still be running.")
        log_warning("project-delete", f"Forced delete despite teardown failure: {detail}",
                    paths, project=project_name)

    rc = 0
    removed_site = False
    for site in (paths.project_caddy_site(project_name),
                 paths.project_staging_caddy_site(project_name)):
        if site.exists():
            site.unlink()
            removed_site = True
    if removed_site:
        try:
            caddy_reload(paths.caddy, paths.state)
        except DockerError as e:
            print(f"ERROR: Caddy reload failed: {e}\n"
                  f"  The deleted project's routes stay live until the next "
                  f"successful reload.", file=sys.stderr)
            log_error("project-delete", f"Caddy reload failed: {e}",
                      paths, project=project_name)
            rc = 1

    remove_project_state(paths, project_name)

    project_dir = paths.project_dir(project_name)
    if project_dir.exists():
        try:
            _remove_project_dir(project_name, project_dir)
        except (ContainersLeft, DockerError, OSError) as e:
            print(f"ERROR: Could not remove {project_dir}: {e}\n  The project is still "
                  f"registered. Fix the cause and run project-delete again.",
                  file=sys.stderr)
            log_error("project-delete", f"Removing the project directory failed: {e}",
                      paths, project=project_name)
            return 1

    if is_registered(project_name, paths):
        registry_remove(project_name, paths)

    log_operation("project-delete", "Project deleted", paths, project=project_name)
    print(f"Project '{project_name}' deleted.")
    _report_kept_volumes(project_name)
    return rc


def _report_kept_volumes(project_name: str) -> None:
    """Named volumes outlive `compose down`, and a new project of the same
    name would mount their old data again: say which are kept."""
    try:
        volumes = [v for p in (project_name, f"{project_name}-staging")
                   for v in docker_containers.project_volumes(p)]
    except DockerError as e:
        print(f"  WARN: could not list the project's Docker volumes ({e}); any named "
              f"volumes were kept (`docker volume ls`).")
        return
    if volumes:
        print(f"  Docker volumes are kept, with their data: {', '.join(volumes)}. A new "
              f"project named '{project_name}' would mount them again. Remove them as "
              f"the supervisor with: docker volume rm {' '.join(volumes)}")


def cmd_project_delete(args: list[str]) -> None:
    # Strict: `project-delete foo --dry-run --yes` used to delete (audit
    # D-03). Any flag other than --yes and --force, including --dry-run,
    # is rejected.
    from boxmunge.commands.argv import parse_args, require_project_name
    parsed = parse_args(
        "project-delete", args, flags={"--yes", "--force"},
        min_positional=1, max_positional=1,
    )
    project = require_project_name("project-delete", parsed.positional[0])
    paths = BoxPaths()
    sys.exit(run_project_delete(
        project, paths, yes=parsed.has("--yes"), force=parsed.has("--force"),
    ))
