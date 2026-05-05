"""boxmunge validate <project> — validate project configuration."""

import json
import sys
from pathlib import Path

from boxmunge.manifest import load_manifest, validate_manifest, ManifestError
from boxmunge.paths import BoxPaths


def _gather_validation(
    project_name: str, paths: BoxPaths,
) -> tuple[list[str], list[str]]:
    """Collect (errors, warnings) for a project. Raises on hard fail.

    Hard fail conditions (project missing, pre-registered, manifest unloadable)
    are surfaced as errors in the returned list — never raise.
    """
    errors: list[str] = []
    warnings: list[str] = []

    project_dir = paths.project_dir(project_name)
    if not project_dir.exists():
        errors.append(f"Project directory not found: {project_dir}")
        return errors, warnings

    if paths.is_project_pre_registered(project_name):
        errors.append(
            f"Project '{project_name}' is pre-registered (secrets set) but "
            f"not yet deployed. Deploy first with: boxmunge deploy {project_name}"
        )
        return errors, warnings

    manifest_path = paths.project_manifest(project_name)
    if not manifest_path.exists():
        errors.append(f"Manifest not found: {manifest_path}")
        return errors, warnings

    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as e:
        errors.append(str(e))
        return errors, warnings

    me, mw = validate_manifest(manifest, project_name)
    errors.extend(me)
    warnings.extend(mw)

    for env_file in manifest.get("env_files", []):
        env_path = project_dir / env_file
        if not env_path.exists():
            warnings.append(f"Environment file missing: {env_file}")

    compose_path = paths.project_compose(project_name)
    if not compose_path.exists():
        warnings.append(f"Compose file missing: {compose_path.name}")

    return errors, warnings


def run_validate(project_name: str, paths: BoxPaths) -> int:
    """Validate a project's manifest and related files.

    Returns 0 on success, 1 on validation failure.
    """
    errors, warnings = _gather_validation(project_name, paths)

    if errors:
        # Surface dir/manifest hard-fail messages with the same ERROR prefix
        # the previous text path used (for backward-compatible scrapers).
        if any(
            e.startswith(("Project directory not found", "Manifest not found"))
            or "pre-registered" in e
            for e in errors
        ):
            for e in errors:
                print(f"ERROR: {e}", file=sys.stderr)
            return 1
        print(f"{project_name}: INVALID")
        for e in errors:
            print(f"  ERROR: {e}", file=sys.stderr)
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


def _run_validate_json(project_name: str, paths: BoxPaths) -> int:
    """Emit the validation result as a single JSON object on stdout."""
    errors, warnings = _gather_validation(project_name, paths)
    payload = {
        "project": project_name,
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
    }
    print(json.dumps(payload))
    return 0 if not errors else 1


def cmd_validate(args: list[str]) -> None:
    """CLI entry point for validate command."""
    as_json = "--json" in args
    positional = [a for a in args if not a.startswith("--")]
    if not positional:
        print("Usage: boxmunge validate <project> [--json]", file=sys.stderr)
        sys.exit(2)

    from boxmunge.paths import validate_project_name
    try:
        validate_project_name(positional[0])
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    paths = BoxPaths()
    if as_json:
        sys.exit(_run_validate_json(positional[0], paths))
    sys.exit(run_validate(positional[0], paths))
