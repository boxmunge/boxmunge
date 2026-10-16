"""boxmunge backup/backup-all/backup-sync commands."""

import enum
import sys
import time
from pathlib import Path

import boxmunge.backup as _backup
from boxmunge.backup import (
    SNAPSHOT_RETENTION, BackupError, BackupKind, backup_filename, prune_backups,
    resolve_backup_service,
)
from boxmunge.backup_dump import execute_dump, remove_stale_dumps
from boxmunge.config import load_config, ConfigError
from boxmunge.fileutil import project_lock, LockError
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.probation import clear_probation_if_active

# Total wall-clock budget for retrying lock-held projects in run_backup_all.
# Bounded so a stuck deploy doesn't keep nightly backup running forever.
_LOCK_RETRY_BUDGET_SECONDS = 30.0
_LOCK_RETRY_INTERVAL_SECONDS = 2.0


class BackupAttemptResult(enum.Enum):
    """Outcome of a single locked-backup attempt (audit I-NEW-2).

    Replaces the previous stringly-typed status (`"ok"` / `"failed"` /
    `"locked"`). Members' ``.value`` matches the original strings so the
    log lines and any external integrations remain unchanged.
    """

    OK = "ok"
    FAILED = "failed"
    LOCKED = "locked"


def sweep_stale_dumps(paths: BoxPaths, project_name: str) -> None:
    """Remove plaintext dumps a killed backup left behind. Caller holds the lock."""
    for stale in remove_stale_dumps(paths, project_name):
        log_warning("backup", f"Removed stale plaintext dump {stale.name} left by an "
                    "interrupted backup", paths, project=project_name)


def list_snapshots(paths: BoxPaths, project_name: str) -> list[Path]:
    """List available backup snapshots for a project, newest first."""
    bdir = paths.project_backups(project_name)
    if not bdir.exists():
        return []
    return sorted(
        bdir.glob(f"{project_name}-*.tar.gz.age"),
        key=lambda f: f.stat().st_mtime,
        reverse=True,
    )


def run_backup(
    project_name: str, paths: BoxPaths, kind: BackupKind = BackupKind.MANUAL,
) -> int:
    """backup: take the project lock and back up. Returns 0 on success, 1 on
    failure."""
    try:
        with project_lock(project_name, paths):
            return backup_locked(project_name, paths, kind=kind)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def backup_locked(
    project_name: str, paths: BoxPaths,
    kind: BackupKind = BackupKind.MANUAL,
    manifest: dict | None = None,
) -> int:
    """The backup core. Caller holds the project lock; never takes it.

    ``kind`` tags the snapshot and selects its retention: the manifest's
    ``backup.retention`` for nightly backups, SNAPSHOT_RETENTION otherwise.

    ``manifest`` overrides the one on disk: promote backs up production data
    with the production release's backup config while the staged release's
    files are on disk.

    Paused projects refuse with rc=1 (operator-driven backup against a
    paused project is almost certainly wrong). Quarantined projects skip
    cleanly with rc=0 (cron-driven backup-all should not fail just
    because a project is offline for security reasons; volume-empty
    warnings would be noise). Different rc shapes preserved by reason.
    """
    block = is_blocked(project_name, paths)
    if block and block.reason is BlockReason.PAUSED:
        print(f"ERROR: {block.refuse_message}", file=sys.stderr)
        return 1
    if block and block.reason is BlockReason.QUARANTINED:
        # Backups of stopped services are pointless and would emit
        # confusing "volume empty" warnings — skip cleanly with a
        # structured log entry, returning 0.
        print(
            f"{project_name}: skipping backup — CVE-quarantined "
            f"(use `boxmunge security resume` to lift)",
        )
        log_operation(
            "backup", block.skip_message,
            paths, project=project_name,
        )
        return 0
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists():
        print(f"ERROR: Project not found: {project_name}", file=sys.stderr)
        return 1

    if paths.is_project_pre_registered(project_name):
        print(f"ERROR: Project '{project_name}' is pre-registered (secrets set) but "
              f"not yet deployed. Deploy first with: boxmunge deploy {project_name}", file=sys.stderr)
        return 1

    if manifest is None:
        try:
            manifest = load_manifest(paths.project_manifest(project_name))
        except ManifestError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1

    backup_conf = manifest.get("backup", {})
    backup_type = backup_conf.get("type", "none")

    if backup_type == "none":
        print(f"{project_name}: no backup configured (type: none)")
        return 0

    dump_command = backup_conf.get("dump_command", "")
    if not dump_command:
        print(f"ERROR: backup type is '{backup_type}' but no dump_command defined", file=sys.stderr)
        return 1

    try:
        service = resolve_backup_service(manifest)
    except BackupError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    retention = (backup_conf.get("retention", 7) if kind is BackupKind.NIGHTLY
                 else SNAPSHOT_RETENTION[kind])
    if type(retention) is not int or retention < 1:
        print(f"ERROR: backup.retention must be a whole number of at least 1, "
              f"got {retention!r}", file=sys.stderr)
        return 1
    key_path = paths.backup_key

    if not key_path.exists():
        print(f"ERROR: Backup encryption key not found: {key_path}", file=sys.stderr)
        return 1

    return _run_backup_inner(
        project_name, paths, dump_command, service, kind, retention,
    )


def _run_backup_inner(
    project_name: str,
    paths: BoxPaths,
    dump_command: str,
    service: str,
    kind: BackupKind,
    retention: int,
) -> int:
    print(f"{project_name}: starting {kind.value} backup (service: {service})...")
    sweep_stale_dumps(paths, project_name)

    try:
        raw_path = execute_dump(paths, project_name, dump_command, service)
    except BackupError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        log_error("backup", f"Backup dump failed: {e}", paths, project=project_name)
        return 1

    fname = backup_filename(project_name, kind)
    try:
        _backup.encrypt_file(raw_path, paths.project_backups(project_name) / fname, paths)
    except (BackupError, FileNotFoundError) as e:
        print(f"ERROR: Encryption failed: {e}", file=sys.stderr)
        log_error("backup", f"Backup encrypt failed: {e}", paths, project=project_name)
        return 1
    finally:
        raw_path.unlink(missing_ok=True)

    pruned = prune_backups(paths.project_backups(project_name), project_name, kind, retention)
    if pruned:
        print(f"  Pruned {len(pruned)} old {kind.value} backup(s)")

    log_operation("backup", f"Backup completed: {fname}", paths, project=project_name)
    print(f"{project_name}: backup complete -> {fname}")
    return 0


def _attempt_locked_backup(name: str, paths: BoxPaths) -> BackupAttemptResult:
    """Attempt a single backup under the project lock (audit I-NEW-2).

    Returns:
      - ``BackupAttemptResult.OK``     — backup succeeded (rc 0)
      - ``BackupAttemptResult.FAILED`` — backup ran but returned non-zero
      - ``BackupAttemptResult.LOCKED`` — project lock was held by another op
    """
    try:
        with project_lock(name, paths):
            rc = backup_locked(name, paths, kind=BackupKind.NIGHTLY)
    except LockError:
        return BackupAttemptResult.LOCKED
    return BackupAttemptResult.OK if rc == 0 else BackupAttemptResult.FAILED


def _notify_persistent_locks(paths: BoxPaths, locked: list[str]) -> None:
    """Send a Pushover alert for projects that remained locked through retries.

    Without this, a deploy started just before 02:00 silently consumes its
    project's nightly backup window with no operator-visible signal. Pushover
    is the operator's only out-of-band channel; failures here must surface
    in the log.

    Audit D-NEW-3: the operator must be able to tell "alert sent" from
    "alert dropped"; ``notify`` logs every non-delivery and why.
    """
    if not locked:
        return
    from boxmunge.notify import notify
    names = ", ".join(locked)
    if notify(paths, "backup-all SKIPPED (locked)",
              f"Backup skipped for projects: {names}. They were locked at backup "
              f"time and remained locked through retries — likely a stuck deploy "
              f"or a long-running maintenance op.", component="backup"):
        log_operation(
            "backup",
            f"Pushover sent for {len(locked)} persistent locks",
            paths, detail={"locked": locked},
        )


def run_backup_all(paths: BoxPaths) -> int:
    """Backup all projects that have backup configured.

    For projects whose project_lock is held by another operation (a deploy in
    progress), backups are deferred and retried with a short budget; if the
    lock is still held after retries, the project is reported as locked-skipped
    via Pushover and the run exits with status 1 so the operator has visibility.
    """
    projects_dir = paths.projects
    if not projects_dir.exists():
        print("No projects directory.")
        return 0

    projects = sorted(
        p.name for p in projects_dir.iterdir()
        if p.is_dir() and (p / "manifest.yml").exists()
    )

    if not projects:
        print("No projects to backup.")
        return 0

    failed: list[str] = []
    locked: list[str] = []

    # First pass: try every unblocked project once. Skip paused/quarantined
    # cleanly — quarantined gets a structured log entry; paused historically
    # only printed (preserved).
    for name in projects:
        block = is_blocked(name, paths)
        if block and block.reason is BlockReason.PAUSED:
            print(f"  Skipping {name}: paused.")
            continue
        if block and block.reason is BlockReason.QUARANTINED:
            print(f"  Skipping {name}: CVE-quarantined.")
            log_operation(
                "backup", block.skip_message,
                paths, project=name,
            )
            continue
        result = _attempt_locked_backup(name, paths)
        if result == BackupAttemptResult.OK:
            continue
        if result == BackupAttemptResult.LOCKED:
            locked.append(name)
            print(f"  {name}: locked, will retry")
            # Audit E-NEW-4: surface the first-pass lock skip in the
            # structured log too (previously only printed to stdout).
            log_operation(
                "backup", "locked, retrying", paths, project=name,
            )
            continue
        failed.append(name)

    # Bounded retry pass for locked projects: a deploy that's wrapping up
    # should release its lock within seconds; a stuck op never will. Don't
    # let nightly backup hang on a single project.
    if locked:
        deadline = time.monotonic() + _LOCK_RETRY_BUDGET_SECONDS
        still_locked: list[str] = []
        for name in locked:
            if time.monotonic() >= deadline:
                still_locked.append(name)
                continue
            outcome: BackupAttemptResult = BackupAttemptResult.LOCKED
            while time.monotonic() < deadline:
                outcome = _attempt_locked_backup(name, paths)
                if outcome != BackupAttemptResult.LOCKED:
                    break
                time.sleep(_LOCK_RETRY_INTERVAL_SECONDS)
            if outcome == BackupAttemptResult.OK:
                # Audit E-NEW-4: forensic trail for retry success.
                log_operation(
                    "backup", "backup completed after retry",
                    paths, project=name,
                )
                continue
            if outcome == BackupAttemptResult.FAILED:
                failed.append(name)
            else:
                still_locked.append(name)
        locked = still_locked

    if locked:
        log_warning(
            "backup",
            f"backup-all skipped (locked): {', '.join(locked)}",
            paths, detail={"locked": locked},
        )
        _notify_persistent_locks(paths, locked)

    if failed or locked:
        return 1
    return 0


def run_backup_sync(paths: BoxPaths, project_name: str | None = None) -> int:
    """Copy encrypted backups to the configured remote with rclone.

    ``rclone copy``, never ``sync``: the remote is an archive, not a mirror,
    so a local prune or ``project-delete`` never deletes an off-site copy.
    Off-site retention is the remote's job (for example a bucket lifecycle
    rule). Layout on the remote: ``<remote>/<project>/backups/<snapshot>``.
    """
    try:
        config = load_config(paths)
    except ConfigError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    remote = config.get("backup_remote", "")
    if not remote:
        print("ERROR: backup_remote not configured in boxmunge.yml", file=sys.stderr)
        return 1

    if project_name:
        src = paths.project_backups(project_name)
        dest = f"{remote}/{project_name}/backups"
        include = "/*.tar.gz.age"
    else:
        src = paths.projects
        dest = remote
        include = "/*/backups/*.tar.gz.age"

    print(f"Copying backups to {dest}...")

    from boxmunge.system_container import RCLONE_CONFIG, SystemContainerError, connect

    try:
        tools = connect(paths)
        tools.run(["rclone", "copy", tools.path(src), dest,
                   "--include", include,
                   "--config", RCLONE_CONFIG])
    except SystemContainerError as e:
        print(f"ERROR: rclone copy failed: {e}", file=sys.stderr)
        log_error("backup", f"Backup sync to {dest} failed: {e}", paths)
        return 1

    log_operation("backup", f"Backup sync to {dest} completed", paths)
    print("Backup sync complete.")
    return 0


def cmd_backup(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name
    parsed = parse_args("backup", args, min_positional=1, max_positional=1)
    project = require_project_name("backup", parsed.positional[0])
    paths = BoxPaths()
    # An operator's backup ends upgrade probation (the operator is looking at
    # the box). run_backup itself does not: the nightly backup-all timer,
    # container-update and self-test call it too (C-07).
    clear_probation_if_active(paths, "backup")
    sys.exit(run_backup(project, paths))


def cmd_backup_all(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args
    parse_args("backup-all", args)
    paths = BoxPaths()
    sys.exit(run_backup_all(paths))


def cmd_backup_sync(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name
    parsed = parse_args("backup-sync", args, max_positional=1)
    project = None
    if parsed.positional:
        project = require_project_name("backup-sync", parsed.positional[0])
    paths = BoxPaths()
    sys.exit(run_backup_sync(paths, project))
