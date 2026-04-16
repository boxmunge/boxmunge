# SPDX-License-Identifier: Apache-2.0
"""boxmunge deploy <project> — full deployment flow."""

import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from boxmunge.caddy import generate_caddy_config
from boxmunge.compose import generate_compose_override
from boxmunge.config import load_config, ConfigError
from boxmunge.docker import compose_up, caddy_reload, DockerError
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.manifest import load_manifest, validate_manifest, ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.state import read_state, write_state


def record_deploy_state(
    paths: BoxPaths,
    project_name: str,
    ref: str,
    snapshot: str | None,
) -> None:
    """Record a deploy in the state file, pushing previous to history."""
    state_path = paths.project_deploy_state(project_name)
    current = read_state(state_path)

    history = current.get("history", [])
    if "current_ref" in current:
        history.insert(0, {
            "ref": current["current_ref"],
            "deployed_at": current.get("deployed_at", ""),
            "snapshot": current.get("pre_deploy_snapshot", ""),
        })
        history = history[:10]

    new_state = {
        "current_ref": ref,
        "deployed_at": datetime.now(timezone.utc).isoformat(),
        "pre_deploy_snapshot": snapshot or "",
        "history": history,
    }

    write_state(state_path, new_state)


def prepare_caddy_config(paths: BoxPaths, manifest: dict[str, Any]) -> None:
    """Generate or copy Caddy site config for a project."""
    project_name = manifest["project"]
    site_conf = paths.project_caddy_site(project_name)
    site_conf.parent.mkdir(parents=True, exist_ok=True)

    override = paths.project_caddy_override(project_name)
    if override.exists():
        site_conf.write_text(override.read_text())
        log_operation("deploy", f"Using custom Caddy config from {override.name}", paths, project=project_name)
    else:
        config = generate_caddy_config(manifest)
        site_conf.write_text(config)


def prepare_compose_override(paths: BoxPaths, manifest: dict[str, Any]) -> None:
    """Generate compose.boxmunge.yml for a project."""
    project_name = manifest["project"]
    override_path = paths.project_compose_override(project_name)
    override_path.parent.mkdir(parents=True, exist_ok=True)

    # Build env_files based on which files exist
    env_files = {}
    if paths.host_secrets.exists():
        env_files["host_secrets"] = str(paths.host_secrets)
    project_env = paths.project_dir(project_name) / "project.env"
    if project_env.exists():
        env_files["project_env"] = "./project.env"
    project_secrets = paths.project_secrets(project_name)
    if project_secrets.exists():
        env_files["project_secrets"] = "./secrets.env"

    content = generate_compose_override(manifest, env_files=env_files or None)
    override_path.write_text(content)


def run_deploy(
    project_name: str,
    paths: BoxPaths,
    ref: str | None = None,
    no_snapshot: bool = False,
    dry_run: bool = False,
) -> int:
    """Execute the full deploy flow. Returns 0 on success, 1 on failure."""
    project_dir = paths.project_dir(project_name)

    # Resolve from inbox for new projects and bundle-source upgrades.
    # Git projects have a repo/ dir; bundle projects don't — so for bundles
    # we always check the inbox for a newer upload.
    is_new = not project_dir.exists() or not (project_dir / "manifest.yml").exists()
    is_bundle_project = is_new or not (project_dir / "repo").exists()

    if is_bundle_project:
        from boxmunge.source import resolve_bundle_source, SourceError
        from boxmunge.bundle import extract_bundle as _extract_bundle, copy_project_files as _copy_project_files
        from boxmunge.identity import check_project_identity, register_project_identity
        import tempfile
        import shutil as _shutil

        try:
            bundle_path = resolve_bundle_source(project_name, paths, ref=ref)
        except SourceError:
            if is_new:
                print(f"ERROR: No bundles for '{project_name}' in inbox and no existing project.")
                return 1
            # Existing project, no new bundle — redeploy what's on disk
            bundle_path = None

        if bundle_path is not None:
            with tempfile.TemporaryDirectory() as tmpdir:
                try:
                    extracted = _extract_bundle(bundle_path, Path(tmpdir))
                except ValueError as e:
                    print(f"ERROR: {e}")
                    return 1

                manifest_path_extracted = extracted / "manifest.yml"
                if not manifest_path_extracted.exists():
                    print("ERROR: Bundle missing manifest.yml")
                    return 1

                try:
                    manifest_data = load_manifest(manifest_path_extracted)
                except ManifestError as e:
                    print(f"ERROR: {e}")
                    return 1

                errors_check, warnings_check = validate_manifest(manifest_data, project_name)
                if errors_check:
                    print("ERROR: Manifest validation failed:")
                    for err in errors_check:
                        print(f"  {err}")
                    return 1

                manifest_id = manifest_data.get("id", "")
                try:
                    check_project_identity(project_name, manifest_id, paths)
                except ValueError as e:
                    print(f"ERROR: {e}")
                    return 1

                if dry_run:
                    print(f"[DRY RUN] Would deploy '{project_name}' from bundle")
                    return 0

                action = "Creating" if is_new else "Updating"
                print(f"{action} project '{project_name}' from bundle...")
                project_dir.mkdir(parents=True, exist_ok=True)
                _copy_project_files(extracted, project_dir, is_upgrade=not is_new)

            register_project_identity(project_name, manifest_id, paths)

            # Move bundle to consumed
            paths.inbox_consumed.mkdir(parents=True, exist_ok=True)
            _shutil.move(str(bundle_path), str(paths.inbox_consumed / bundle_path.name))

            # Clear ref since we already resolved the source
            ref = None

    if not project_dir.exists():
        print(f"ERROR: Project not found: {project_dir}")
        return 1

    manifest_path = paths.project_manifest(project_name)
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as e:
        print(f"ERROR: {e}")
        return 1

    errors, warnings = validate_manifest(manifest, project_name)
    if errors:
        print(f"ERROR: Manifest validation failed:")
        for e in errors:
            print(f"  {e}")
        return 1
    for w in warnings:
        print(f"  WARN: {w}")

    deploy_ref = ref or manifest.get("ref", "main")

    if dry_run:
        print(f"[DRY RUN] Would deploy {project_name} at ref {deploy_ref}")
        print(f"[DRY RUN] Would generate Caddy config and compose override")
        print(f"[DRY RUN] Would start containers and reload Caddy")
        return 0

    print(f"Deploying {project_name} (ref: {deploy_ref})...")

    # Pull code
    repo_dir = project_dir / "repo"
    repo_url = manifest.get("repo", "")
    if repo_url and repo_dir.exists():
        print(f"  Pulling {deploy_ref}...")
        try:
            subprocess.run(
                ["git", "fetch", "origin"], cwd=repo_dir, check=True,
                capture_output=True, text=True,
            )
            subprocess.run(
                ["git", "checkout", deploy_ref], cwd=repo_dir, check=True,
                capture_output=True, text=True,
            )
            subprocess.run(
                ["git", "pull", "--ff-only", "origin", deploy_ref],
                cwd=repo_dir, check=False, capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"  ERROR: Git pull failed: {e.stderr}")
            return 1

    # Get current ref
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_dir if repo_dir.exists() else project_dir,
            capture_output=True, text=True, check=True,
        )
        actual_ref = result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        actual_ref = deploy_ref

    # Pre-deploy snapshot
    snapshot_name = None
    snapshot_enabled = manifest.get("deploy", {}).get("snapshot_before_deploy", True)
    backup_type = manifest.get("backup", {}).get("type", "none")
    if snapshot_enabled and not no_snapshot and backup_type != "none":
        print(f"  Taking pre-deploy snapshot...")
        from boxmunge.commands.backup_cmd import run_backup
        backup_result = run_backup(project_name, paths)
        if backup_result != 0:
            print(f"  WARN: Pre-deploy backup failed — continuing deploy")
        else:
            from boxmunge.commands.backup_cmd import list_snapshots
            snaps = list_snapshots(paths, project_name)
            if snaps:
                snapshot_name = snaps[0].name

    # Pre-deploy command
    pre_deploy = manifest.get("deploy", {}).get("pre_deploy", "")
    if pre_deploy:
        print(f"  Running pre-deploy: {pre_deploy}")
        try:
            subprocess.run(
                shlex.split(pre_deploy), shell=False, cwd=project_dir, check=True,
                capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"  ERROR: Pre-deploy failed: {e.stderr}")
            return 1

    # Generate configs
    print(f"  Generating Caddy config...")
    prepare_caddy_config(paths, manifest)

    print(f"  Generating compose overlay...")
    prepare_compose_override(paths, manifest)

    # Start containers
    print(f"  Starting containers...")
    compose_files = ["compose.yml", "compose.boxmunge.yml"]
    try:
        compose_up(project_dir, compose_files=compose_files)
    except DockerError as e:
        print(f"  ERROR: {e}")
        log_error("deploy", f"Deploy failed: container start: {e}", paths, project=project_name)
        return 1

    # Reload Caddy
    print(f"  Reloading Caddy...")
    try:
        caddy_reload(paths.caddy)
    except DockerError as e:
        print(f"  WARN: Caddy reload failed: {e}")

    # Per-service smoke tests — exec inside each container
    has_smoke = any(svc.get("smoke") for svc in manifest.get("services", {}).values())
    if has_smoke:
        print(f"  Running smoke tests in containers...")
        from boxmunge.commands.check import run_smoke_in_container, should_downgrade_smoke_failure
        smoke_result = run_smoke_in_container(
            project_dir, manifest, compose_files,
        )
        if smoke_result.status == "ok":
            print(f"  Smoke tests passed.")
        elif should_downgrade_smoke_failure(project_name, paths):
            print(f"  WARN: Smoke test {smoke_result.status} (first deploy — downgraded to warning): {smoke_result.message}")
            log_warning("deploy", f"First deploy smoke {smoke_result.status} downgraded: {smoke_result.message}",
                        paths, project=project_name)
        else:
            print(f"  WARN: Smoke test {smoke_result.status}: {smoke_result.message}")

    # Record state
    record_deploy_state(paths, project_name, actual_ref, snapshot_name)

    # Log
    log_operation("deploy", f"Deploy completed ref={actual_ref}", paths, project=project_name, detail={"ref": actual_ref})
    print(f"{project_name}: deployed successfully (ref: {actual_ref})")

    try:
        from boxmunge.config import load_config
        from boxmunge.webhooks import fire_webhook
        config = load_config(paths)
        fire_webhook("deploy", project_name, config, details={"ref": actual_ref})
    except Exception:
        pass

    return 0


def cmd_deploy(args: list[str]) -> None:
    """CLI entry point for deploy command."""
    if not args:
        print("Usage: boxmunge deploy <project> [--ref REF] [--no-snapshot] [--dry-run]",
              file=sys.stderr)
        sys.exit(2)

    project = args[0]

    from boxmunge.paths import validate_project_name
    try:
        validate_project_name(project)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    ref = None
    no_snapshot = False
    dry_run = False

    remaining = args[1:]
    i = 0
    while i < len(remaining):
        if remaining[i] == "--ref" and i + 1 < len(remaining):
            ref = remaining[i + 1]
            i += 2
        elif remaining[i] == "--no-snapshot":
            no_snapshot = True
            i += 1
        elif remaining[i] == "--dry-run":
            dry_run = True
            i += 1
        else:
            i += 1

    paths = BoxPaths()
    exit_code = run_deploy(project, paths, ref=ref, no_snapshot=no_snapshot,
                           dry_run=dry_run)
    sys.exit(exit_code)
