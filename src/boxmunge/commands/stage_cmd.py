"""boxmunge stage <project> — stage from latest source alongside production."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.caddy import generate_staging_caddy_config
from boxmunge.bundle import extract_bundle as _extract_bundle, copy_project_files as _copy_project_files
from boxmunge.compose import generate_staging_compose_override
from boxmunge.docker import compose_up, caddy_reload, DockerError
from boxmunge.identity import check_project_identity, register_project_identity
from boxmunge.log import log_operation, log_error
from boxmunge.manifest import load_manifest, validate_manifest, ManifestError
from boxmunge.project_registry import is_registered
from boxmunge.source import resolve_bundle_source, SourceError
from boxmunge.state import write_state

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def run_stage(project_name: str, paths: BoxPaths, ref: str | None = None,
              dry_run: bool = False) -> int:
    project_dir = paths.project_dir(project_name)

    if not is_registered(project_name, paths):
        print(f"ERROR: Project '{project_name}' is not registered on this server. "
              f"Run: project-add {project_name}")
        return 1

    is_new = not project_dir.exists() or not (project_dir / "manifest.yml").exists()

    # Resolve source for bundle projects (new or no repo)
    if is_new or not (project_dir / "repo").exists():
        try:
            bundle_path = resolve_bundle_source(project_name, paths, ref=ref)
        except SourceError as e:
            print(f"ERROR: {e}")
            return 1

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                extracted = _extract_bundle(bundle_path, Path(tmpdir))
            except ValueError as e:
                print(f"ERROR: {e}")
                return 1

            manifest_path = extracted / "manifest.yml"
            if not manifest_path.exists():
                print("ERROR: Bundle missing manifest.yml")
                return 1

            try:
                manifest = load_manifest(manifest_path)
            except ManifestError as e:
                print(f"ERROR: {e}")
                return 1

            errors, warnings = validate_manifest(manifest, project_name)
            if errors:
                print("ERROR: Manifest validation failed:")
                for e in errors:
                    print(f"  {e}")
                return 1
            for w in warnings:
                print(f"  WARN: {w}")

            manifest_id = manifest.get("id", "")
            try:
                check_project_identity(project_name, manifest_id, paths)
            except ValueError as e:
                print(f"ERROR: {e}")
                return 1

            if dry_run:
                print(f"[DRY RUN] Would stage '{project_name}'")
                return 0

            if is_new:
                print(f"Creating new project '{project_name}'")
                project_dir.mkdir(parents=True, exist_ok=True)

            _copy_project_files(extracted, project_dir, is_upgrade=not is_new)

        register_project_identity(project_name, manifest_id, paths)

        # Move bundle to consumed
        paths.inbox_consumed.mkdir(parents=True, exist_ok=True)
        shutil.move(str(bundle_path), str(paths.inbox_consumed / bundle_path.name))
    else:
        # Git-based or existing project — load manifest from project dir
        try:
            manifest = load_manifest(paths.project_manifest(project_name))
        except ManifestError as e:
            print(f"ERROR: {e}")
            return 1

        # For git projects, fetch and checkout the requested ref
        repo_dir = project_dir / "repo"
        if repo_dir.exists() and ref:
            print(f"  Fetching ref {ref}...")
            try:
                subprocess.run(["git", "fetch", "origin"], cwd=repo_dir,
                               check=True, capture_output=True, text=True)
                subprocess.run(["git", "checkout", ref], cwd=repo_dir,
                               check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                print(f"ERROR: Git checkout failed: {e.stderr}")
                return 1

        if dry_run:
            print(f"[DRY RUN] Would stage '{project_name}'")
            return 0

    # Generate staging configs
    print(f"Staging {project_name}...")
    staging_conf = paths.project_staging_caddy_site(project_name)
    staging_conf.parent.mkdir(parents=True, exist_ok=True)
    staging_conf.write_text(generate_staging_caddy_config(manifest))

    # Build env_files for staging (same as production)
    staging_env_files = {}
    if paths.host_secrets.exists():
        staging_env_files["host_secrets"] = str(paths.host_secrets)
    project_env = project_dir / "project.env"
    if project_env.exists():
        staging_env_files["project_env"] = "./project.env"
    project_secrets = paths.project_secrets(project_name)
    if project_secrets.exists():
        staging_env_files["project_secrets"] = "./secrets.env"

    staging_override = paths.project_staging_compose_override(project_name)
    staging_override.write_text(generate_staging_compose_override(
        manifest, env_files=staging_env_files or None
    ))

    # Start staging containers with separate project name
    print(f"  Starting staging containers...")
    staging_project_name = f"{project_name}-staging"
    compose_files = ["compose.yml", "compose.boxmunge-staging.yml"]
    try:
        compose_up(project_dir, compose_files=compose_files,
                   project_name=staging_project_name)
    except DockerError as e:
        print(f"  ERROR: {e}")
        log_error("stage", f"Stage failed: {e}", paths, project=project_name)
        return 1

    # Reload Caddy
    print(f"  Reloading Caddy...")
    try:
        caddy_reload(paths.caddy)
    except DockerError as e:
        print(f"  WARN: Caddy reload failed: {e}")

    # Per-service smoke tests — exec inside staging containers
    has_smoke = any(svc.get("smoke") for svc in manifest.get("services", {}).values())
    if has_smoke:
        print(f"  Running smoke tests in containers...")
        from boxmunge.commands.check import run_smoke_in_container
        staging_compose_files = ["compose.yml", "compose.boxmunge-staging.yml"]
        smoke_result = run_smoke_in_container(
            project_dir, manifest, staging_compose_files,
            project_name=staging_project_name,
        )
        if smoke_result.status == "ok":
            print(f"  Smoke tests passed.")
        else:
            print(f"  WARN: Smoke test {smoke_result.status}: {smoke_result.message}")

    # Record staging state
    write_state(paths.project_staging_state(project_name), {
        "active": True,
        "ref": ref or "latest",
    })

    staging_hosts = [f"staging.{h}" for h in manifest.get("hosts", [])]
    print(f"  Staged at:")
    for h in staging_hosts:
        print(f"    https://{h}")
    print(f"  Run 'promote {project_name}' to go live, or 'unstage {project_name}' to tear down.")

    log_operation("stage", "Staged", paths, project=project_name)

    try:
        from boxmunge.config import load_config
        from boxmunge.webhooks import fire_webhook
        config = load_config(paths)
        fire_webhook("stage", project_name, config, details={"ref": ref or "latest"})
    except Exception:
        pass

    return 0


def cmd_stage(args: list[str]) -> None:
    from boxmunge.paths import BoxPaths
    if not args:
        print("Usage: boxmunge stage <project> [--ref REF] [--dry-run]", file=sys.stderr)
        sys.exit(2)
    project = args[0]

    from boxmunge.paths import validate_project_name
    try:
        validate_project_name(project)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    ref = None
    dry_run = False
    remaining = args[1:]
    i = 0
    while i < len(remaining):
        if remaining[i] == "--ref" and i + 1 < len(remaining):
            ref = remaining[i + 1]
            i += 2
        elif remaining[i] == "--dry-run":
            dry_run = True
            i += 1
        else:
            i += 1
    paths = BoxPaths()
    sys.exit(run_stage(project, paths, ref=ref, dry_run=dry_run))
