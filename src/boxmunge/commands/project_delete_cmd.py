# SPDX-License-Identifier: Apache-2.0
"""boxmunge project-delete <project> — destructive removal: containers, files, registry.

Containers (production and staging) are torn down first. If that fails,
nothing is deleted: the compose files are what a retry needs to reach the
containers. ``--force`` deletes anyway and warns that containers may be
left running. On success every per-project file goes, including pause and
quarantine markers, so a project later created with the same name starts
clean.
"""

import shutil
import sys
from pathlib import Path

from boxmunge.docker import compose_down, caddy_reload, remove_built_images, DockerError
from boxmunge.fileutil import LockError, project_lock
from boxmunge.log import log_error, log_operation, log_warning
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import is_registered, remove_project as registry_remove


def project_state_files(paths: BoxPaths, name: str) -> list[Path]:
    """Every per-project file kept outside the project directory.

    The project lock file (``state/<name>.lock``) is deliberately absent:
    project-delete holds that lock, and unlinking a lock file in use would
    let a new opener lock a fresh inode alongside the current holder.
    """
    return [
        paths.project_health_state(name),
        paths.project_deploy_state(name),
        paths.project_paused_state(name),
        paths.project_quarantine_state(name),
        paths.project_scan_state(name),
        paths.project_staging_state(name),
        paths.container_update_target_state(name),
    ]


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
                         project_name=project_name)
        except DockerError as e:
            failures.append(f"production: {e}")
    if paths.project_staging_compose_override(project_name).exists():
        base = ("compose.staging-base.yml"
                if (project_dir / "compose.staging-base.yml").exists() else "compose.yml")
        try:
            compose_down(project_dir, compose_files=[base, "compose.boxmunge-staging.yml"],
                         project_name=f"{project_name}-staging")
        except DockerError as e:
            failures.append(f"staging: {e}")
    # Only the images the platform built for this project: their names
    # (boxmunge.invalid/<compose-project>/...) belong to no one else.
    for compose_project in (project_name, f"{project_name}-staging"):
        try:
            remove_built_images(compose_project)
        except DockerError as e:
            failures.append(f"built images of {compose_project}: {e}")
    return failures


def delete_locked(project_name: str, paths: BoxPaths, force: bool) -> int:
    """Tear down and remove the project. Caller holds the project lock."""
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

    for state_file in project_state_files(paths, project_name):
        state_file.unlink(missing_ok=True)

    project_dir = paths.project_dir(project_name)
    if project_dir.exists():
        shutil.rmtree(project_dir)

    if is_registered(project_name, paths):
        registry_remove(project_name, paths)

    log_operation("project-delete", "Project deleted", paths, project=project_name)
    print(f"Project '{project_name}' deleted.")
    return rc


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
