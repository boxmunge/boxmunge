"""boxmunge import <bundle.tar.gz> — import and deploy a project from a bundle.

The bundle is filed in the inbox exactly as an upload would be, then deployed
through the same validate-before-install path as `prod-deploy`, so an import
can never put an unvalidated tree on disk.
"""

import shutil
import sys
from pathlib import Path

from boxmunge.commands.deploy import run_deploy
from boxmunge.intake import (
    IntakeError, extract_candidate, incoming_workspace, report_refusal,
    validate_release_tree,
)
from boxmunge.fileutil import project_lock, LockError
from boxmunge.log import log_operation, log_error
from boxmunge.paths import BoxPaths, validate_project_name
from boxmunge.project_registry import is_registered
from boxmunge.reception import peek_manifest_from_bundle, receive_bundle
from boxmunge.source import bundle_ref


def _dry_run(bundle_path: Path, project_name: str, paths: BoxPaths) -> int:
    try:
        with project_lock(project_name, paths):
            with incoming_workspace(paths, project_name) as workspace:
                tree = extract_candidate(bundle_path, workspace)
                validate_release_tree(tree, project_name, paths, "import")
    except IntakeError as e:
        return report_refusal(e)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print(f"[DRY RUN] Bundle is valid; would import and deploy '{project_name}'")
    return 0


def run_import(
    bundle_path_str: str,
    paths: BoxPaths,
    yes: bool = False,
    dry_run: bool = False,
) -> int:
    """Import and deploy a project from a tar.gz bundle.

    Returns 0 on success, 1 on failure, 3 for a compose hardening rejection.
    """
    bundle_path = Path(bundle_path_str).expanduser().resolve()
    try:
        manifest = peek_manifest_from_bundle(bundle_path)
        project_name = manifest.get("project", "")
        validate_project_name(project_name)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if not is_registered(project_name, paths):
        print(f"ERROR: Project '{project_name}' is not registered on this server. "
              f"Run: project-add {project_name}", file=sys.stderr)
        return 1

    if dry_run:
        return _dry_run(bundle_path, project_name, paths)

    is_upgrade = paths.project_manifest(project_name).exists()
    if is_upgrade and not yes:
        print(f"Upgrading existing project '{project_name}'")
        print("  This replaces the project's code with the bundle's "
              "(secrets, data, backups and suppressions are kept)")
        response = input("  Proceed? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            return 1

    # File a copy in the inbox the way an upload is filed, then deploy
    # exactly that bundle.
    paths.inbox_tmp.mkdir(parents=True, exist_ok=True)
    filed_copy = paths.inbox_tmp / bundle_path.name
    shutil.copy2(bundle_path, filed_copy)
    try:
        filed = receive_bundle(filed_copy, paths)
    except ValueError as e:
        filed_copy.unlink(missing_ok=True)
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    result = run_deploy(project_name, paths, ref=bundle_ref(filed), component="import")
    if result != 0:
        log_error("import", "Import deploy failed", paths, project=project_name)
        return result

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
