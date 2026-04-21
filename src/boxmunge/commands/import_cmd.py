"""boxmunge import <bundle.tar.gz> — import and deploy a project from a bundle."""

import os
import shutil
import sys
import tempfile
from pathlib import Path

from boxmunge.bundle import extract_bundle, copy_project_files
from boxmunge.commands.deploy import run_deploy
from boxmunge.fileutil import project_lock, LockError
from boxmunge.log import log_operation, log_error
from boxmunge.manifest import load_manifest, validate_manifest, ManifestError
from boxmunge.paths import BoxPaths

# Module-level aliases used by stage_cmd and deploy (underscore names are the
# public API surface for internal callers — kept here to avoid a wide rename).
_extract_bundle = extract_bundle
_copy_project_files = copy_project_files


def run_import(
    bundle_path_str: str,
    paths: BoxPaths,
    yes: bool = False,
    dry_run: bool = False,
) -> int:
    """Import and deploy a project from a tar.gz bundle.

    Returns 0 on success, 1 on failure.
    """
    bundle_path = Path(bundle_path_str).expanduser().resolve()

    # Step 1: Extract to temp dir
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            project_dir_extracted = _extract_bundle(bundle_path, Path(tmpdir))
        except ValueError as e:
            print(f"ERROR: {e}")
            return 1

        project_name = project_dir_extracted.name

        # Step 2: Validate manifest
        manifest_path = project_dir_extracted / "manifest.yml"
        if not manifest_path.exists():
            print(f"ERROR: Bundle missing manifest.yml")
            return 1

        compose_path = project_dir_extracted / "compose.yml"
        if not compose_path.exists():
            print(f"ERROR: Bundle missing compose.yml")
            return 1

        try:
            manifest = load_manifest(manifest_path)
        except ManifestError as e:
            print(f"ERROR: {e}")
            return 1

        errors, warnings = validate_manifest(manifest, project_name)
        if errors:
            print(f"ERROR: Bundle manifest is invalid:")
            for e in errors:
                print(f"  {e}")
            return 1
        for w in warnings:
            print(f"  WARN: {w}")

        # Step 3: Determine new vs upgrade
        target_dir = paths.project_dir(project_name)
        is_upgrade = target_dir.exists() and (target_dir / "manifest.yml").exists()

        if dry_run:
            mode = "upgrade" if is_upgrade else "new project"
            print(f"[DRY RUN] Would import '{project_name}' as {mode}")
            print(f"[DRY RUN] Bundle is valid")
            return 0

        if is_upgrade:
            print(f"Upgrading existing project '{project_name}'")
            if not yes:
                print(f"  This will update project files (project.env preserved)")
                response = input("  Proceed? [y/N] ")
                if response.lower() != "y":
                    print("Aborted.")
                    return 1
        else:
            print(f"Creating new project '{project_name}'")

        # Acquire lock before any file mutations
        try:
            with project_lock(project_name, paths):
                if not is_upgrade:
                    target_dir.mkdir(parents=True, exist_ok=True)

                # Step 4: Handle project.env for new projects
                if not is_upgrade:
                    env_in_bundle = project_dir_extracted / "project.env"
                    env_example = project_dir_extracted / "project.env.example"
                    if not env_in_bundle.exists() and env_example.exists():
                        shutil.copy2(env_example, env_in_bundle)
                        print(f"  WARN: No project.env in bundle — copied from "
                              f"project.env.example. Edit it with real values.")

                # Step 5: Copy files
                print(f"  Copying project files...")
                _copy_project_files(project_dir_extracted, target_dir, is_upgrade)

                # Step 6: Deploy using standard flow (lock already held)
                print(f"  Running deploy...")
                result = run_deploy(project_name, paths, _lock_held=True)
                if result != 0:
                    log_error("import", "Import deploy failed", paths, project=project_name)
                    return 1
        except LockError as e:
            print(f"ERROR: {e}")
            return 1

    log_operation("import", f"Imported from bundle: {bundle_path.name}", paths, project=project_name)
    return 0


def cmd_import(args: list[str]) -> None:
    """CLI entry point for import command."""
    yes = "--yes" in args
    dry_run = "--dry-run" in args

    positional = [a for a in args if not a.startswith("--")]
    if not positional:
        print("Usage: boxmunge import <bundle.tar.gz> [--yes] [--dry-run]",
              file=sys.stderr)
        sys.exit(2)

    bundle = positional[0]
    paths = BoxPaths()
    sys.exit(run_import(bundle, paths, yes=yes, dry_run=dry_run))
