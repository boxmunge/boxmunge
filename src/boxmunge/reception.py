# SPDX-License-Identifier: Apache-2.0
"""Bundle reception — validate and file incoming bundles to the inbox."""

from __future__ import annotations

import shutil
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def peek_manifest_from_bundle(bundle_path: Path) -> dict[str, Any]:
    """Read and parse manifest.yml from inside a tar.gz bundle without extracting.

    The bundle must contain exactly one top-level directory with a manifest.yml.
    Returns the parsed manifest dict.
    Raises ValueError if the bundle is invalid or manifest is missing.
    """
    if not bundle_path.exists():
        raise ValueError(f"Bundle not found: {bundle_path}")

    try:
        valid = tarfile.is_tarfile(bundle_path)
    except (EOFError, OSError):
        valid = False
    if not valid:
        raise ValueError(f"Not a valid tar.gz file: {bundle_path}")

    with tarfile.open(bundle_path, "r:gz") as tar:
        # Find manifest.yml — expect it at <project>/manifest.yml
        manifest_member = None
        for member in tar.getmembers():
            parts = Path(member.name).parts
            if len(parts) == 2 and parts[1] == "manifest.yml":
                manifest_member = member
                break

        if manifest_member is None:
            raise ValueError(
                f"No manifest.yml found in bundle: {bundle_path}. "
                "Expected <project>/manifest.yml at the top level."
            )

        f = tar.extractfile(manifest_member)
        if f is None:
            raise ValueError(f"Cannot read manifest.yml from bundle: {bundle_path}")

        data = yaml.safe_load(f)

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
