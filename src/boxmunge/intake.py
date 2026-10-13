# SPDX-License-Identifier: Apache-2.0
"""Release intake: unpack and validate a candidate tree before it goes live.

Every bundle is extracted into ``<project>/.releases/incoming/`` and checked
there (manifest, identity, user compose hardening). Only a candidate that
passes every check is installed over the live project tree, so a rejected
bundle never reaches the files that root timers later ``compose up``
(audit C-01 / A-02).
"""
from __future__ import annotations

import shutil
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from boxmunge.bundle import extract_bundle
from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.identity import check_project_identity
from boxmunge.log import log_error
from boxmunge.manifest import ManifestError, load_manifest, validate_manifest
from boxmunge.security_overlay import services_with_off_profile

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

# Exit code reserved for compose hardening rejections (audit H-N2).
EXIT_COMPOSE_REJECTED = 3


class IntakeError(Exception):
    """A candidate release was refused. Carries the command's exit code."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@contextmanager
def incoming_workspace(paths: BoxPaths, project_name: str) -> Iterator[Path]:
    """Yield an empty ``.releases/incoming/`` dir, removed again on exit.

    Directories this creates (the project dir of a first deploy, the
    ``.releases`` dir) are removed too if they end up empty, so a refused
    first deploy leaves nothing behind. The caller holds the project lock,
    so a leftover ``incoming/`` can only be debris from a crashed run.
    """
    project_dir = paths.project_dir(project_name)
    releases = paths.project_releases(project_name)
    created_project = not project_dir.exists()
    created_releases = not releases.exists()
    incoming = releases / "incoming"
    if incoming.exists():
        shutil.rmtree(incoming)
    incoming.mkdir(parents=True)
    try:
        yield incoming
    finally:
        shutil.rmtree(incoming)
        if created_releases and not any(releases.iterdir()):
            releases.rmdir()
        if created_project and not any(project_dir.iterdir()):
            project_dir.rmdir()


def extract_candidate(bundle_path: Path, workspace: Path) -> Path:
    """Extract a bundle into the workspace and return its project tree."""
    try:
        return extract_bundle(bundle_path, workspace)
    except ValueError as e:
        raise IntakeError(str(e)) from e


def validate_release_tree(
    tree: Path, project_name: str, paths: BoxPaths, component: str,
) -> dict[str, Any]:
    """Run every pre-install check on a release tree; return its manifest.

    Raises IntakeError (exit 1, or 3 for a compose hardening rejection).
    Warnings are printed; nothing on disk is changed.
    """
    manifest_path = tree / "manifest.yml"
    if not manifest_path.exists():
        raise IntakeError("Release is missing manifest.yml")
    if not (tree / "compose.yml").exists():
        raise IntakeError("Release is missing compose.yml")
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as e:
        raise IntakeError(str(e)) from e

    errors, warnings = validate_manifest(manifest, project_name)
    if errors:
        detail = "\n".join(f"  {err}" for err in errors)
        raise IntakeError(f"Manifest validation failed:\n{detail}")
    for w in warnings:
        print(f"  WARN: {w}")

    try:
        check_project_identity(project_name, manifest.get("id", ""), paths)
    except ValueError as e:
        raise IntakeError(str(e)) from e

    # User compose is checked against silent-floor-defeating keys before any
    # overlay exists: compose's multi-file merge would otherwise let a user
    # `privileged: true` win over the boxmunge baseline.
    off_services = {svc for svc, _ in services_with_off_profile(manifest)}
    try:
        validate_user_compose(
            tree / "compose.yml", paths,
            off_services=off_services,
            project_name=project_name,
            cve_policy=manifest.get("security"),
            manifest_services=manifest.get("services"),
        )
    except ComposeSecurityError as e:
        log_error(component, f"Compose validation rejected: {e}",
                  paths, project=project_name)
        raise IntakeError(str(e), exit_code=EXIT_COMPOSE_REJECTED) from e
    return manifest


def report_refusal(e: IntakeError) -> int:
    """Print an intake refusal to stderr and return its exit code."""
    print(f"ERROR: {e}", file=sys.stderr)
    return e.exit_code
