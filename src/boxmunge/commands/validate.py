"""boxmunge validate <project> — validate project configuration."""

import sys
from pathlib import Path

from boxmunge.manifest import load_manifest, validate_manifest, ManifestError
from boxmunge.paths import BoxPaths


def run_validate(project_name: str, paths: BoxPaths) -> int:
    """Validate a project's manifest and related files.

    Returns 0 on success, 1 on validation failure.
    """
    project_dir = paths.project_dir(project_name)

    if not project_dir.exists():
        print(f"ERROR: Project directory not found: {project_dir}")
        return 1

    if paths.is_project_pre_registered(project_name):
        print(f"ERROR: Project '{project_name}' is pre-registered (secrets set) but "
              f"not yet deployed. Deploy first with: boxmunge deploy {project_name}")
        return 1

    manifest_path = paths.project_manifest(project_name)
    if not manifest_path.exists():
        print(f"ERROR: Manifest not found: {manifest_path}")
        return 1

    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as e:
        print(f"ERROR: {e}")
        return 1

    errors, warnings = validate_manifest(manifest, project_name)

    for env_file in manifest.get("env_files", []):
        env_path = project_dir / env_file
        if not env_path.exists():
            warnings.append(f"Environment file missing: {env_file}")

    compose_path = paths.project_compose(project_name)
    if not compose_path.exists():
        warnings.append(f"Compose file missing: {compose_path.name}")

    if errors:
        print(f"{project_name}: INVALID")
        for e in errors:
            print(f"  ERROR: {e}")
        for w in warnings:
            print(f"  WARN:  {w}")
        return 1

    if warnings:
        print(f"{project_name}: VALID (with warnings)")
        for w in warnings:
            print(f"  WARN:  {w}")
    else:
        print(f"{project_name}: VALID")

    return 0


def cmd_validate(args: list[str]) -> None:
    """CLI entry point for validate command."""
    if not args:
        print("Usage: boxmunge validate <project>", file=sys.stderr)
        sys.exit(2)

    from boxmunge.paths import validate_project_name
    try:
        validate_project_name(args[0])
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    paths = BoxPaths()
    exit_code = run_validate(args[0], paths)
    sys.exit(exit_code)
