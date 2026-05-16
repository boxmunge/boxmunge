# SPDX-License-Identifier: Apache-2.0
"""boxmunge resume <project> — bring a paused project back online safely.

By default, pulls the latest images for all `image:` services before
starting the project. This closes the window where a long-paused project
could come back online with stale, vulnerable container images.

The --skip-security-checks flag bypasses the pre-resume image pull. Use
only when the operator explicitly accepts the risk (e.g., registry outage).
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

from boxmunge.caddy import prepare_caddy_config
from boxmunge.compose import prepare_compose_override
from boxmunge.compose_validate import validate_user_compose, ComposeSecurityError
from boxmunge.docker import (
    compose_pull, compose_up, caddy_reload, DockerError,
)
from boxmunge.health_checks.smoke import run_smoke
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.pause import is_paused, clear_paused_state
from boxmunge.paths import BoxPaths, validate_project_name
from boxmunge.pushover import send_notification
from boxmunge.security_overlay import services_with_off_profile
from boxmunge.state import read_state, write_state


def _has_image_services(project_dir: Path, compose_files: list[str]) -> bool:
    """True if any service in any of the compose files declares `image:`."""
    for cf in compose_files:
        path = project_dir / cf
        if not path.exists():
            continue
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError:
            continue
        services = data.get("services", {})
        for svc in services.values():
            if isinstance(svc, dict) and svc.get("image"):
                return True
    return False


def run_resume(
    project_name: str,
    paths: BoxPaths,
    yes: bool = False,
    skip_security_checks: bool = False,
) -> int:
    """Resume a paused project. Returns 0 on success, 1 on failure."""
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists() or not (project_dir / "manifest.yml").exists():
        print(f"ERROR: Project not found: {project_name}", file=sys.stderr)
        return 1

    # Pause-resume must NOT silently un-quarantine. Lifting CVE quarantine
    # has its own dedicated command path (`boxmunge security resume`)
    # which re-scans before lifting. is_blocked() returns QUARANTINED
    # first if both states exist (quarantine wins), so the refuse
    # message is the security one.
    block = is_blocked(project_name, paths)
    if block and block.reason is BlockReason.QUARANTINED:
        print(f"ERROR: {block.refuse_message}", file=sys.stderr)
        return 1

    # Positive precondition: this command can only be invoked when the
    # project is paused. Note this is a different semantic from the
    # is_blocked refuse path above.
    if not is_paused(project_name, paths):
        print(f"ERROR: Project '{project_name}' is not paused.",
              file=sys.stderr)
        return 1

    try:
        manifest = load_manifest(paths.project_manifest(project_name))
    except ManifestError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    compose_files = ["compose.yml"]
    override = paths.project_compose_override(project_name)
    if override.exists():
        compose_files.append("compose.boxmunge.yml")

    pull_image_services = _has_image_services(project_dir, compose_files)

    if not yes:
        print(f"This will resume '{project_name}':")
        if skip_security_checks:
            print("  - SKIPPING image pull (--skip-security-checks set)")
        elif pull_image_services:
            print("  - Pull latest images (security check)")
        else:
            print("  - No image: services to pull")
        print("  - Start containers")
        print("  - Restore Caddy routing + run smoke test")
        response = input("\nProceed? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            return 1

    # Validate user compose.yml against silent-floor-defeating keys BEFORE
    # any container action. A hostile compose.yml introduced while the
    # project was paused must not survive even an image pull or compose_up
    # — reject before touching containers (audit A-NEW-1). Mirrors the
    # ordering used in deploy/stage.
    off_services = {svc for svc, _ in services_with_off_profile(manifest)}
    try:
        validate_user_compose(
            paths.project_compose(project_name), paths,
            off_services=off_services,
            project_name=project_name,
            cve_policy=manifest.get("security"),
            manifest_services=manifest.get("services"),
        )
    except ComposeSecurityError as e:
        # Exit code 3 reserved for compose hardening rejections (audit H-N2).
        print(f"ERROR: {e}", file=sys.stderr)
        log_error("resume", f"Compose validation rejected: {e}",
                  paths, project=project_name)
        return 3

    # Pull images (unless overridden or no image: services).
    if pull_image_services and not skip_security_checks:
        print("  Pulling latest images...")
        try:
            compose_pull(project_dir, compose_files=compose_files,
                         project_name=project_name)
        except DockerError as e:
            print(f"ERROR: Image pull failed: {e}", file=sys.stderr)
            print("       Use --skip-security-checks to resume without "
                  "pulling (accepts vulnerability risk).",
                  file=sys.stderr)
            log_error("resume", f"Image pull failed: {e}", paths,
                      project=project_name)
            return 1

    # Start containers.
    print("  Starting containers...")
    try:
        compose_up(project_dir, compose_files=compose_files)
    except DockerError as e:
        print(f"ERROR: compose up failed: {e}", file=sys.stderr)
        log_error("resume", f"compose up failed: {e}", paths,
                  project=project_name)
        return 1

    # Restore Caddy site config from manifest (regenerated).
    print("  Restoring Caddy routing...")
    try:
        prepare_caddy_config(paths, manifest)
        prepare_compose_override(paths, manifest, component="resume")
        caddy_reload(paths.caddy, paths.state)
    except (DockerError, OSError) as e:
        print(f"ERROR: Caddy restore failed: {e}", file=sys.stderr)
        log_error("resume", f"Caddy restore failed: {e}", paths,
                  project=project_name)
        return 1

    # Smoke test.
    print("  Running smoke test...")
    smoke_ok, smoke_msg = run_smoke(project_name, paths)
    if not smoke_ok:
        # Smoke failed. Leave project up, alert, log, but proceed.
        print(f"  WARN: Smoke test failed: {smoke_msg}")
        log_warning("resume", f"Smoke failed after resume: {smoke_msg}",
                    paths, project=project_name)
        try:
            from boxmunge.config import ConfigError, load_config
            cfg = load_config(paths)
            po = cfg.get("pushover", {})
            send_notification(
                po.get("user_key", ""), po.get("app_token", ""),
                "boxmunge resume: smoke failed",
                f"{project_name} resumed but smoke test failed: {smoke_msg}",
            )
        except (ConfigError, OSError, KeyError) as e:
            log_warning("resume", f"could not send Pushover: {e}",
                        paths, project=project_name)

    # Clear paused state (regardless of smoke outcome — project is
    # no longer paused, just possibly unhealthy).
    clear_paused_state(project_name, paths)

    # Bump last_started_at so the health-check grace window kicks in.
    # The 1-second race between resume completion and the container
    # becoming responsive used to surface as a transient FAILING status.
    from datetime import datetime, timezone
    deploy_state_path = paths.project_deploy_state(project_name)
    deploy_state = read_state(deploy_state_path)
    deploy_state["last_started_at"] = datetime.now(timezone.utc).isoformat()
    write_state(deploy_state_path, deploy_state)

    log_operation("resume", "Project resumed", paths,
                  project=project_name,
                  detail={"smoke_ok": smoke_ok, "smoke_msg": smoke_msg})

    print(f"Project '{project_name}' resumed.")
    suffix = f" — {smoke_msg}" if not smoke_ok else ""
    print(f"  Smoke: {'PASS' if smoke_ok else 'FAIL'}{suffix}")
    return 0


def cmd_resume(args: list[str]) -> None:
    if not args:
        print("Usage: boxmunge resume <project> [--skip-security-checks] [--yes]",
              file=sys.stderr)
        sys.exit(2)

    project = args[0]
    try:
        validate_project_name(project)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    yes = "--yes" in args
    skip_security_checks = "--skip-security-checks" in args

    paths = BoxPaths()
    sys.exit(run_resume(project, paths, yes=yes,
                        skip_security_checks=skip_security_checks))
