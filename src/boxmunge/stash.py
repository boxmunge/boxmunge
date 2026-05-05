# SPDX-License-Identifier: Apache-2.0
"""Platform stash — capture state for safe upgrades.

Creates a dated tarball of all project files, config, secrets,
deploy state, and platform version. Used automatically during
boxmunge upgrade; not a user-facing command.
"""

import io
import json
import os
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from boxmunge.fileutil import atomic_write_bytes
from boxmunge.log import log_operation, log_warning
from boxmunge.paths import BoxPaths
from boxmunge.version import read_installed_version

STASH_FORMAT_VERSION = 1
META_FILENAME = "boxmunge-stash-meta.json"


class StashError(Exception):
    """Raised when stash creation or restoration fails safety checks."""


def _meta_payload(paths: BoxPaths) -> dict:
    return {
        "format_version": STASH_FORMAT_VERSION,
        "platform_version": read_installed_version(paths),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def create_stash(paths: BoxPaths) -> Path:
    """Create a stash archive of the current platform state.

    Returns the path to the created archive.
    """
    paths.stashes.mkdir(parents=True, exist_ok=True)
    # Directory ownership/perms are set by install.sh as root:deploy 770.
    # Do not chmod here — that fails when called from deploy context, and
    # would also lock out the deploy group.
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S")
    archive_path = paths.stashes / f"boxmunge-stash-{ts}.tar.gz"

    with tarfile.open(archive_path, "w:gz") as tar:
        for config_file in [paths.config_file, paths.host_secrets, paths.backup_key, paths.version_file]:
            if config_file.exists():
                tar.add(config_file, arcname=f"config/{config_file.name}")

        if paths.deploy_state.exists():
            for state_file in paths.deploy_state.iterdir():
                if state_file.is_file():
                    tar.add(state_file, arcname=f"state/deploy/{state_file.name}")

        if paths.projects.exists():
            for project_dir in sorted(paths.projects.iterdir()):
                if not project_dir.is_dir():
                    continue
                project_name = project_dir.name
                for filename in ["manifest.yml", "compose.yml", "project.env", "secrets.env"]:
                    filepath = project_dir / filename
                    if filepath.exists():
                        tar.add(filepath, arcname=f"projects/{project_name}/{filename}")
                scripts_dir = project_dir / "boxmunge-scripts"
                if scripts_dir.exists():
                    for script in scripts_dir.iterdir():
                        if script.is_file():
                            tar.add(script, arcname=f"projects/{project_name}/boxmunge-scripts/{script.name}")

        # Schema-version marker — must be last so partial archives lack it
        # and are detected as legacy/corrupt by restore_stash.
        meta_bytes = json.dumps(_meta_payload(paths), indent=2).encode()
        meta_info = tarfile.TarInfo(name=META_FILENAME)
        meta_info.size = len(meta_bytes)
        tar.addfile(meta_info, io.BytesIO(meta_bytes))

    os.chmod(archive_path, 0o600)
    log_operation(
        "stash",
        f"Stash created: {archive_path.name}",
        paths,
        detail={"format_version": STASH_FORMAT_VERSION},
    )
    return archive_path


def list_stashes(paths: BoxPaths) -> list[Path]:
    """List stash archives, newest first."""
    if not paths.stashes.exists():
        return []
    return sorted(
        paths.stashes.glob("boxmunge-stash-*.tar.gz"),
        key=lambda f: f.name,
        reverse=True,
    )


def prune_stashes(paths: BoxPaths, keep: int = 3) -> list[Path]:
    """Remove old stashes, keeping the N most recent. Returns pruned paths."""
    stashes = list_stashes(paths)
    to_prune = stashes[keep:]
    for stash in to_prune:
        stash.unlink()
    return to_prune


def _check_member_safe(member: tarfile.TarInfo) -> None:
    """Reject members with traversal/absolute-path/symlink semantics.

    Mirrors the bundle.py guard but uses path-segment matching so that
    'foo..bar' is allowed while 'foo/../bar' is rejected.
    """
    parts = member.name.split("/")
    if member.name.startswith("/") or ".." in parts:
        raise StashError(f"refusing to extract suspicious member name: {member.name!r}")


def _validate_meta(tar: tarfile.TarFile, archive: Path, paths: BoxPaths) -> None:
    """Validate stash schema version. Allows legacy stashes (no meta) with a warning.

    Legacy stashes are stashes created by boxmunge < 0.5.3 (before the meta
    file existed). Real instances of these exist on disk on every fleet
    host, so we treat their absence as "format_version 0" — restorable but
    flagged.
    """
    try:
        meta_member = tar.getmember(META_FILENAME)
    except KeyError:
        log_warning(
            "stash",
            f"stash {archive.name} has no format_version marker — treating as v0",
            paths,
        )
        return

    extracted = tar.extractfile(meta_member)
    if extracted is None:
        raise StashError(f"stash {archive.name}: meta file unreadable")
    try:
        meta = json.loads(extracted.read())
    except json.JSONDecodeError as e:
        raise StashError(f"stash {archive.name}: malformed meta file: {e}") from e

    got = meta.get("format_version")
    if not isinstance(got, int):
        raise StashError(f"stash {archive.name}: format_version must be int, got {got!r}")
    if got > STASH_FORMAT_VERSION:
        raise StashError(
            f"stash format version {got} is newer than this installation "
            f"supports (max {STASH_FORMAT_VERSION}). Upgrade boxmunge-server "
            f"before restoring."
        )


def restore_stash(paths: BoxPaths, archive: Path | None = None) -> Path:
    """Restore platform state from a stash archive.

    If no archive is specified, restores from the most recent stash.
    Extracts config, deploy state, and project files back to their
    original locations. Returns the path to the restored archive.

    Raises FileNotFoundError if the archive or stash directory is empty.
    Raises StashError on schema mismatch or unsafe tar contents.
    """
    if archive is None:
        stashes = list_stashes(paths)
        if not stashes:
            raise FileNotFoundError("No stashes available to restore")
        archive = stashes[0]

    if not archive.exists():
        raise FileNotFoundError(f"Stash not found: {archive}")

    config_root = paths.config.resolve()
    deploy_root = paths.deploy_state.resolve()
    projects_root = paths.projects.resolve()

    with tarfile.open(archive, "r:gz") as tar:
        _validate_meta(tar, archive, paths)

        for member in tar.getmembers():
            if member.name == META_FILENAME:
                continue

            _check_member_safe(member)

            if member.name.startswith("config/"):
                target = paths.config / member.name.removeprefix("config/")
                expected_root = config_root
            elif member.name.startswith("state/deploy/"):
                target = paths.deploy_state / member.name.removeprefix("state/deploy/")
                expected_root = deploy_root
            elif member.name.startswith("projects/"):
                target = paths.projects / member.name.removeprefix("projects/")
                expected_root = projects_root
            else:
                continue

            # Apply tarfile's data filter: rejects symlinks, devices, absolute
            # paths (defence in depth on top of _check_member_safe).
            try:
                tarfile.data_filter(member, str(target.parent))
            except tarfile.FilterError as e:
                raise StashError(
                    f"refusing to extract member {member.name!r}: {e}"
                ) from e

            # Resolve-and-contain: ensure the final target is within an
            # expected root. Use parent.resolve() because target itself may
            # not yet exist; the parent's resolved path tells us what the
            # final location will be.
            target.parent.mkdir(parents=True, exist_ok=True)
            resolved = (target.parent.resolve() / target.name)
            try:
                resolved.relative_to(expected_root)
            except ValueError as e:
                raise StashError(
                    f"refusing to extract member {member.name!r}: "
                    f"resolves outside expected directories"
                ) from e

            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            extracted = tar.extractfile(member)
            if extracted is not None:
                atomic_write_bytes(target, extracted.read())

    log_operation("stash", f"Stash restored from: {archive.name}", paths)
    return archive
