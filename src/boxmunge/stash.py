# SPDX-License-Identifier: Apache-2.0
"""Platform stash — capture state for safe upgrades.

Creates a dated tarball of all project files, config, secrets,
deploy state, and platform version. Used automatically during
boxmunge upgrade; not a user-facing command.
"""

import io
import json
import os
import pwd
import tarfile
from contextlib import AbstractContextManager, nullcontext
from datetime import datetime, timezone
from pathlib import Path

from boxmunge.fileutil import atomic_write_bytes, open_regular_nofollow
from boxmunge.git_layout import LINKED_FILES, links_into_repo
from boxmunge.log import log_operation, log_warning
from boxmunge.paths import BoxPaths
from boxmunge.secrets import SecretsFile
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


_PROJECT_FILES = ("manifest.yml", "compose.yml", "project.env", "secrets.env")


def _git_link(path: Path) -> bool:
    """A git project's manifest.yml or compose.yml, linked into its checkout.

    The link is the checkout's, not state to roll back: it is left out of
    the stash, stays on disk, and restore never touches it.
    """
    return path.name in LINKED_FILES and links_into_repo(path.parent, path.name)


def _stash_set(paths: BoxPaths) -> list[tuple[Path, str]]:
    """(path, arcname) of every file to stash, all regular files.

    Raises StashError, before anything is written, naming every other
    symlink: a stash holds only file contents, so a rollback could not put
    a link back, and refusing now (before the upgrade changes anything)
    costs nothing.
    """
    found: list[tuple[Path, str]] = []
    links: list[Path] = []

    def take(path: Path, arcname: str) -> None:
        if path.is_symlink():
            links.append(path)
        elif path.is_file():
            found.append((path, arcname))

    for config_file in [paths.config_file, paths.host_secrets, paths.backup_key, paths.version_file]:
        take(config_file, f"config/{config_file.name}")
    if paths.deploy_state.exists():
        for state_file in sorted(paths.deploy_state.iterdir()):
            take(state_file, f"state/deploy/{state_file.name}")
    if paths.projects.exists():
        for project_dir in sorted(paths.projects.iterdir()):
            if project_dir.is_symlink():
                links.append(project_dir)
                continue
            if not project_dir.is_dir():
                continue
            arcdir = f"projects/{project_dir.name}"
            for filename in _PROJECT_FILES:
                if not _git_link(project_dir / filename):
                    take(project_dir / filename, f"{arcdir}/{filename}")
            scripts_dir = project_dir / "boxmunge-scripts"
            if scripts_dir.is_symlink():
                links.append(scripts_dir)
            elif scripts_dir.is_dir():
                for script in sorted(scripts_dir.iterdir()):
                    take(script, f"{arcdir}/boxmunge-scripts/{script.name}")
    if links:
        listed = "\n".join(f"  {link} -> {os.readlink(link)}" for link in links)
        raise StashError(
            f"Cannot stash: these are symlinks, and a stash holds only regular "
            f"files (except a git project's manifest.yml and compose.yml linking "
            f"into its repo/), so a rollback could not restore them:\n{listed}\n"
            f"Replace each with what it points to (cp --remove-destination "
            f"\"$(readlink -f <path>)\" <path>, or move the directory into place) "
            f"or remove it, then retry. Nothing has been changed.")
    return found


def create_stash(paths: BoxPaths) -> Path:
    """Create a stash archive of the current platform state.

    Returns the path to the created archive. Raises StashError, writing
    nothing, if the state includes a symlink it cannot hold (_stash_set).
    """
    members = _stash_set(paths)
    paths.stashes.mkdir(parents=True, exist_ok=True)
    # Directory ownership/perms are set by install.sh as root:deploy 770.
    # Do not chmod here — that fails when called from deploy context, and
    # would also lock out the deploy group.
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S")
    archive_path = paths.stashes / f"boxmunge-stash-{ts}.tar.gz"

    # stashes/ is deploy-writable (root:deploy 770), and root creates stashes
    # too: never follow a planted symlink at this predictable name.
    raw = os.fdopen(open_regular_nofollow(
        archive_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb")
    os.fchmod(raw.fileno(), 0o600)
    with raw, tarfile.open(fileobj=raw, mode="w:gz") as tar:
        for path, arcname in members:
            tar.add(path, arcname=arcname)

        # Schema-version marker — must be last so partial archives lack it
        # and are detected as legacy/corrupt by restore_stash.
        meta_bytes = json.dumps(_meta_payload(paths), indent=2).encode()
        meta_info = tarfile.TarInfo(name=META_FILENAME)
        meta_info.size = len(meta_bytes)
        tar.addfile(meta_info, io.BytesIO(meta_bytes))

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


# Pause and quarantine markers record what an operator or the CVE scanner did
# after the stash was taken. Restoring an old marker would mark a running
# project paused (so backups and health checks skip it); dropping a new one
# would put a quarantined project back in rotation. They are left as they are.
_LIFECYCLE_MARKER_SUFFIXES = (".paused.json", ".quarantined.json")


def _is_lifecycle_marker(member_name: str) -> bool:
    return member_name.startswith("state/deploy/") and member_name.endswith(
        _LIFECYCLE_MARKER_SUFFIXES
    )


def _allowed_owner(member: tarfile.TarInfo) -> tuple[int, int] | None:
    """The (uid, gid) to restore, or None when not running as root.

    The stash directory is writable by deploy, so the recorded owner is only
    trusted if it is root or deploy; anything else stops the restore.
    """
    if os.geteuid() != 0:
        return None
    deploy = pwd.getpwnam("deploy")
    if member.uid not in (0, deploy.pw_uid) or member.gid not in (0, deploy.pw_gid):
        raise StashError(
            f"refusing to restore {member.name!r}: recorded owner "
            f"{member.uid}:{member.gid} is neither root nor deploy"
        )
    return member.uid, member.gid


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


def _secrets_lock(paths: BoxPaths, member_name: str) -> AbstractContextManager:
    """The writer lock for a secrets file, so a restore cannot interleave
    with a concurrent `secrets set` that would write back older contents."""
    if member_name == f"config/{paths.host_secrets.name}":
        return SecretsFile.host(paths).locked()
    parts = member_name.split("/")
    if len(parts) == 3 and parts[0] == "projects" and parts[2] == "secrets.env":
        return SecretsFile.project(paths, parts[1]).locked()
    return nullcontext()


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
            if member.name == META_FILENAME or _is_lifecycle_marker(member.name):
                continue

            _check_member_safe(member)

            # Stashes made before links were left out hold a git project's
            # manifest.yml and compose.yml as links into its checkout. The
            # links are still on disk; refusing them would abort the rollback.
            if member.issym():
                log_warning("stash", f"Skipped symlink member {member.name!r} "
                            f"(left as it is on disk)", paths)
                continue

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
            # A stash made while an older upgrade had replaced the link with
            # a file must not undo the operator's re-link.
            if member.name.startswith("projects/") and _git_link(target):
                log_warning("stash", f"Skipped {member.name!r}: on disk it links "
                            f"into the project's repo/ (left as it is)", paths)
                continue

            extracted = tar.extractfile(member)
            if extracted is not None:
                owner = _allowed_owner(member)
                # Permission bits only: never setuid/setgid/sticky from an archive.
                # Owner set on the temp's descriptor: chown by name after the
                # rename would follow a symlink swapped in meanwhile.
                with _secrets_lock(paths, member.name):
                    atomic_write_bytes(target, extracted.read(), mode=member.mode & 0o777,
                                       owner=owner)

    log_operation("stash", f"Stash restored from: {archive.name}", paths)
    return archive
