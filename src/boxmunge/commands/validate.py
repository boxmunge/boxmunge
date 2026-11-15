"""boxmunge validate <project> — validate project configuration.

It runs the checks a deploy runs on the release before anything changes
(intake.validate_release_tree): the manifest, the scripts it names, and
compose.yml against the hardening, isolation and posture rules. So a
project validate passes is one prod-deploy does not refuse for its
configuration; a compose rejection exits 3, as the deploy's does.
"""

import json
import sys
from typing import NamedTuple

from boxmunge.compose_validate import ComposeSecurityError
from boxmunge.identity import check_project_identity
from boxmunge.intake import EXIT_COMPOSE_REJECTED, check_release_compose, scripts_problems
from boxmunge.manifest import (
    ManifestError, at_current_schema, load_manifest_as_written, validate_manifest,
)
from boxmunge.paths import BoxPaths
from boxmunge.user_entries import split_user_entries

# Read by nothing: the overlay always names ./project.env (compose.py).
IGNORED_KEYS = {"env_files": "boxmunge always reads the project's project.env, whatever "
                             "it lists; remove the key from manifest.yml"}


class Validation(NamedTuple):
    errors: list[str]
    warnings: list[str]
    compose_rejection: str | None  # among errors: compose.yml's, which deploy exits 3 for

    @property
    def exit_code(self) -> int:
        """What prod-deploy would exit with for these errors."""
        if self.compose_rejection is not None:
            return EXIT_COMPOSE_REJECTED
        return 1 if self.errors else 0


def gather_validation(project_name: str, paths: BoxPaths) -> Validation:
    """Collect a project's errors and warnings, and the exit code deploy
    would give its refusal. Hard fail conditions (project missing,
    pre-registered, manifest unloadable) are errors too; never raises."""
    errors: list[str] = []
    warnings: list[str] = []

    def done(compose_rejection: str | None = None) -> Validation:
        return Validation(errors, warnings, compose_rejection)

    project_dir = paths.project_dir(project_name)
    if not project_dir.exists():
        errors.append(f"Project directory not found: {project_dir}")
        return done()

    if paths.is_project_pre_registered(project_name):
        errors.append(
            f"Project '{project_name}' is pre-registered (secrets set) but "
            f"not yet deployed. Upload its first bundle, then deploy it with: "
            f"boxmunge prod-deploy {project_name}"
        )
        return done()

    manifest_path = paths.project_manifest(project_name)
    if not manifest_path.exists():
        errors.append(f"Manifest not found: {manifest_path}")
        return done()

    try:
        written = load_manifest_as_written(manifest_path)
    except ManifestError as e:
        errors.append(str(e))
        return done()

    me, mw = validate_manifest(written, project_name)
    errors.extend(me)
    warnings.extend(mw)
    warnings.extend(f"manifest key '{key}' is ignored: {why}"
                    for key, why in IGNORED_KEYS.items() if key in written)

    compose_path = paths.project_compose(project_name)
    if not compose_path.exists():
        errors.append(f"Compose file missing: {compose_path.name}")
        return done()
    if errors:
        return done()  # deploy checks nothing further either
    try:
        manifest = at_current_schema(written, manifest_path)
    except ManifestError as e:
        errors.append(str(e))
        return done()
    try:
        check_project_identity(project_name, manifest.get("id", ""), paths)
    except ValueError as e:
        errors.append(str(e))
        return done()
    errors.extend(scripts_problems(project_dir, manifest))
    try:
        check_release_compose(project_dir, project_name, paths, manifest)
    except ComposeSecurityError as e:
        errors.append(str(e))
        return done(str(e))
    warnings.extend(_undeclared_warnings(
        project_name, split_user_entries(manifest), compose_path))
    return done()


def _undeclared_warnings(project_name: str, manifest: dict, compose_path) -> list[str]:
    """Each service the manifest does not declare, which runs without a
    read-only root filesystem (same warning as deploy and stage)."""
    from boxmunge.compose import ComposeError, load_user_compose
    from boxmunge.security_warn import undeclared_service_warning, undeclared_services

    try:
        user_compose = load_user_compose(compose_path, project_name)
    except ComposeError as e:
        return [f"Cannot resolve compose.yml: {e}"]
    return [
        undeclared_service_warning(project_name, svc).removeprefix("[WARNING] ")
        for svc in undeclared_services(manifest, user_compose)
    ]


def run_validate(project_name: str, paths: BoxPaths) -> int:
    """Validate a project's manifest and related files.

    Returns 0 on success, 1 on validation failure, 3 (as deploy) when
    compose.yml is rejected.
    """
    errors, warnings, _ = validation = gather_validation(project_name, paths)
    code = validation.exit_code

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
            return code
        print(f"{project_name}: INVALID")
        for e in errors:
            print(f"  ERROR: {e}", file=sys.stderr)
        for w in warnings:
            print(f"  WARN:  {w}")
        return code

    if warnings:
        print(f"{project_name}: VALID (with warnings)")
        for w in warnings:
            print(f"  WARN:  {w}")
    else:
        print(f"{project_name}: VALID")

    return 0


def _run_validate_json(project_name: str, paths: BoxPaths) -> int:
    """Emit the validation result as a single JSON object on stdout."""
    errors, warnings, _ = validation = gather_validation(project_name, paths)
    code = validation.exit_code
    payload = {
        "project": project_name,
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
    }
    print(json.dumps(payload))
    return code


def cmd_validate(args: list[str]) -> None:
    """CLI entry point for validate command."""
    known_flags = {"--json"}
    unknown = [a for a in args if a.startswith("--") and a not in known_flags]
    if unknown:
        print(
            f"ERROR: unknown argument(s): {' '.join(unknown)}",
            file=sys.stderr,
        )
        print("Usage: boxmunge validate <project> [--json]", file=sys.stderr)
        sys.exit(2)

    as_json = "--json" in args
    positional = [a for a in args if not a.startswith("--")]
    if not positional:
        print("Usage: boxmunge validate <project> [--json]", file=sys.stderr)
        sys.exit(2)
    if len(positional) > 1:
        print(
            f"ERROR: unknown argument(s): {' '.join(positional[1:])}",
            file=sys.stderr,
        )
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
