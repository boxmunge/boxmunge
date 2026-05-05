# SPDX-License-Identifier: Apache-2.0
"""boxmunge pause <project> — take a project offline with a maintenance page."""
from __future__ import annotations

import sys

from boxmunge.docker import compose_stop, caddy_reload, DockerError
from boxmunge.fileutil import atomic_write_text
from boxmunge.log import log_operation, log_error
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.pause import (
    is_paused, write_paused_state, render_maintenance_caddy_config,
)
from boxmunge.paths import BoxPaths, validate_project_name


def run_pause(
    project_name: str,
    paths: BoxPaths,
    yes: bool = False,
    reason: str | None = None,
) -> int:
    """Pause a project. Returns 0 on success, 1 on failure."""
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists() or not (project_dir / "manifest.yml").exists():
        print(f"ERROR: Project not found: {project_name}", file=sys.stderr)
        return 1

    if is_paused(project_name, paths):
        print(f"ERROR: Project '{project_name}' is already paused.",
              file=sys.stderr)
        return 1

    try:
        manifest = load_manifest(paths.project_manifest(project_name))
    except ManifestError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    hosts = manifest.get("hosts", [])
    if not hosts:
        print(f"ERROR: Project '{project_name}' has no hosts in manifest.",
              file=sys.stderr)
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

    # Write paused.json FIRST so any subsequent failure leaves status as PAUSED.
    write_paused_state(project_name, paths, reason=reason)

    # Swap Caddy site config BEFORE stopping containers — visitors should
    # never see "504 Bad Gateway" between container stop and config swap.
    try:
        site_conf = render_maintenance_caddy_config(hosts)
        atomic_write_text(paths.project_caddy_site(project_name),
                          site_conf, mode=0o644)
        caddy_reload(paths.caddy)
    except (DockerError, OSError) as e:
        print(f"ERROR: Failed to swap Caddy config: {e}", file=sys.stderr)
        log_error("pause", f"Caddy swap failed: {e}", paths,
                  project=project_name)
        return 1

    # Now stop the containers.
    compose_files = ["compose.yml"]
    override = paths.project_compose_override(project_name)
    if override.exists():
        compose_files.append("compose.boxmunge.yml")
    try:
        compose_stop(project_dir, compose_files=compose_files)
    except DockerError as e:
        print(f"WARN: compose stop reported errors: {e}", file=sys.stderr)
        log_error("pause", f"compose stop warning: {e}", paths,
                  project=project_name)

    log_operation("pause", "Project paused", paths,
                  project=project_name,
                  detail={"reason": reason} if reason else None)
    print(f"Project '{project_name}' paused.")
    print(f"  Visitors to {', '.join(hosts)} see the maintenance page.")
    print(f"  Run 'resume {project_name}' to bring back online.")
    return 0


def cmd_pause(args: list[str]) -> None:
    if not args:
        print("Usage: boxmunge pause <project> [--reason \"text\"] [--yes]",
              file=sys.stderr)
        sys.exit(2)

    project = args[0]
    try:
        validate_project_name(project)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    yes = "--yes" in args
    reason: str | None = None
    if "--reason" in args:
        i = args.index("--reason")
        if i + 1 >= len(args):
            print("ERROR: --reason requires a value", file=sys.stderr)
            sys.exit(2)
        reason = args[i + 1]

    paths = BoxPaths()
    sys.exit(run_pause(project, paths, yes=yes, reason=reason))
