# SPDX-License-Identifier: Apache-2.0
"""Bundle reception — validate and file incoming bundles to the inbox."""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from boxmunge.bundle import inspect_bundle

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def peek_manifest_from_bundle(bundle_path: Path) -> dict[str, Any]:
    """Read and parse manifest.yml from inside a tar.gz bundle without extracting.

    The archive is read through the bounded inspection extraction uses
    (bundle.inspect_bundle), so an upload over a limit, or laid out as no
    deploy would accept, is refused here, and the manifest is capped before
    YAML parses it. Returns the parsed manifest dict.
    Raises ValueError if the bundle is invalid or manifest is missing.
    """
    found = inspect_bundle(bundle_path)
    if found.manifest is None:
        raise ValueError(
            f"No manifest.yml found in bundle: {bundle_path}. "
            f"Expected <project>/manifest.yml at the top level."
        )
    try:
        data = yaml.safe_load(found.manifest)
    except (yaml.YAMLError, RecursionError) as e:  # RecursionError: nesting too deep
        raise ValueError(f"manifest.yml is not valid YAML in: {bundle_path}: "
                         f"{type(e).__name__}: {e}") from e

    if not isinstance(data, dict):
        raise ValueError(f"manifest.yml is not a YAML mapping in: {bundle_path}")

    return data


def receive_bundle(source_path: Path, paths: BoxPaths) -> Path:
    """Validate an uploaded bundle and move it to the inbox.

    1. Peeks at the manifest to extract the project name.
    2. Generates a timestamped filename: <project>-<ISO8601>.tar.gz
    3. Moves the bundle to the inbox directory.

    Returns the final path in the inbox.
    Raises ValueError if the bundle is invalid.
    """
    # Reject empty/tiny files that can't be valid tar.gz
    if not source_path.exists():
        raise ValueError(f"Bundle not found: {source_path}")
    if source_path.stat().st_size == 0:
        raise ValueError(f"Not a valid tar.gz file: {source_path} (empty file)")

    manifest = peek_manifest_from_bundle(source_path)

    project_name = manifest.get("project", "")
    if not project_name:
        raise ValueError(
            f"Bundle manifest is missing 'project' field: {source_path}"
        )
    if not isinstance(project_name, str):
        raise ValueError(
            f"Bundle manifest's 'project' must be a project name, not "
            f"{project_name!r}: {source_path}"
        )

    from boxmunge.paths import validate_project_name
    try:
        validate_project_name(project_name)
    except ValueError as e:
        raise ValueError(f"Bundle has invalid project name: {e}") from e

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S%f")
    filename = f"{project_name}-{timestamp}.tar.gz"
    dest = paths.inbox / filename

    paths.inbox.mkdir(parents=True, exist_ok=True)

    shutil.move(str(source_path), str(dest))
    return dest
