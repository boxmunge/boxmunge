"""boxmunge backup and backup-all commands (backup-sync: backup_sync_cmd)."""

import enum
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import boxmunge.backup as _backup
from boxmunge.backup_source import backup_source
from boxmunge.backup import (
    SNAPSHOT_RETENTION, BackupError, BackupKind, backup_filename,
    resolve_backup_service,
)
from boxmunge.backup_alerts import deliver
from boxmunge.backup_dump import execute_dump, remove_stale_dumps
from boxmunge.backup_evidence import record_excused, record_failure, record_snapshot
from boxmunge.fileutil import project_lock, LockError
from boxmunge.fleet import PROJECT_INPUT_ERRORS, report_project_failure
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.manifest import ManifestError
from boxmunge.manifest_fields import retention_problem
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.probation import clear_probation_if_active
from boxmunge.release import ReleaseStateError
from boxmunge.snapshot_pairings import prune_unpaired

# Total wall-clock budget for retrying lock-held projects in run_backup_all.
# Bounded so a stuck deploy doesn't keep nightly backup running forever.
_LOCK_RETRY_BUDGET_SECONDS = 30.0
_LOCK_RETRY_INTERVAL_SECONDS = 2.0


@dataclass(frozen=True)
class BackupResult:
    """What one run of the backup core did.

    rc 0 with a snapshot: it was published at exactly that path. rc 0
    without one: none was due (type none, a quarantined project), unless
    `cause` says backup_source skipped it, which it alerted. rc 1: the
    backup failed, and `cause` says why."""

    rc: int
    snapshot: Path | None = None
    cause: str | None = None

    def __post_init__(self) -> None:
        if self.rc != 0 and not self.cause:
            raise ValueError("a failed backup must say why")


def _failed(cause: str) -> BackupResult:
    print(f"ERROR: {cause}", file=sys.stderr)
    return BackupResult(1, cause=cause)


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
    """List available backup snapshots for a project, newest first.

    backups/ is deploy-writable, so an entry there may be a link (dangling,
    or to a file boxmunge did not write) or anything else: it is skipped
    with a warning, never stat()ed through."""
    bdir = paths.project_backups(project_name)
    if not bdir.exists():
        return []
    found: list[tuple[float, Path]] = []
    for path in bdir.glob(f"{project_name}-*.tar.gz.age"):
        try:
            st = path.lstat()
        except FileNotFoundError:
            continue  # removed meanwhile (prune)
        if not stat.S_ISREG(st.st_mode):
            log_warning("backup", f"Skipped {path}: not a regular file (a link or "
                        f"other entry boxmunge did not write). Remove it.", paths,
                        project=project_name)
            continue
        found.append((st.st_mtime, path))
    return [path for _, path in sorted(found, key=lambda item: item[0], reverse=True)]


def take_snapshot(
    project_name: str, paths: BoxPaths, kind: BackupKind, manifest: dict | None = None,
    compose_file: Path | None = None, *, offline: bool = False,
) -> tuple[int, str | None]:
    """The backup core's rc, and the name of the snapshot it published: the
    core says which, so it is never another backup's. The name is None
    when it wrote none, whose rc is 0 too: type none, a skip (a quarantined
    project, or backup_source's). Caller holds the project lock."""
    if offline:
        result = snapshot_locked(project_name, paths, kind=kind, manifest=manifest,
                                 compose_file=compose_file, offline=True)
    else:
        result = snapshot_locked(project_name, paths, kind=kind, manifest=manifest,
                                 compose_file=compose_file)
    return result.rc, (result.snapshot.name if result.snapshot is not None else None)


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
    compose_file: Path | None = None,
    offline: bool = False,
) -> int:
    """snapshot_locked, for a caller that needs only its exit code."""
    return snapshot_locked(project_name, paths, kind, manifest, compose_file, offline).rc


def snapshot_locked(
    project_name: str, paths: BoxPaths,
    kind: BackupKind = BackupKind.MANUAL,
    manifest: dict | None = None,
    compose_file: Path | None = None,
    offline: bool = False,
) -> BackupResult:
    """The backup core. Caller holds the project lock; never takes it.

    ``kind`` tags the snapshot and selects its retention: the manifest's
    ``backup.retention`` for nightly backups, SNAPSHOT_RETENTION otherwise.

    Without ``manifest``, the backup uses the manifest of the release the
    containers run (backup_source: during an open install that may not be
    the project dir's). ``manifest`` overrides the choice: the pre-deploy
    snapshot passes production's own, read before any install starts, and
    promote passes the production release's while the staged release's
    files are on disk. ``compose_file`` goes with it when the running
    release's compose file is not the project dir's (an open install).

    Paused projects refuse with rc=1 (operator-driven backup against a
    paused project is almost certainly wrong). Quarantined projects skip
    cleanly with rc=0 (cron-driven backup-all should not fail just
    because a project is offline for security reasons; volume-empty
    warnings would be noise). Different rc shapes preserved by reason.

    ``offline`` (data chown, over a stopped backup service) dumps in a
    one-off container of the service instead (backup_offline): the data is
    at rest, so a pause or a quarantine does not stop it.
    """
    block = is_blocked(project_name, paths)
    if block and block.reason is BlockReason.MIGRATING or (
            block and block.reason is BlockReason.PAUSED and not offline):
        return _failed(block.refuse_message)
    if block and block.reason is BlockReason.QUARANTINED and not offline:
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
        return BackupResult(0)
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists():
        return _failed(f"Project not found: {project_name}")

    if paths.is_project_pre_registered(project_name):
        return _failed(f"Project '{project_name}' is pre-registered (secrets set) but "
                       f"not yet deployed. Upload its first bundle, then deploy it with: "
                       f"boxmunge prod-deploy {project_name}")

    if manifest is None:
        try:
            source = backup_source(paths, project_name)
        except (ManifestError, ReleaseStateError) as e:
            return _failed(str(e))
        if source.manifest is None:
            print(f"{project_name}: backup skipped: {source.skip}")
            log_operation("backup", f"Backup skipped: {source.skip}", paths,
                          project=project_name)
            if source.alert:
                notify(paths, f"{project_name}: backup skipped", source.skip,
                       component="backup", project=project_name, priority=1)
                return BackupResult(0, cause=source.skip)
            return BackupResult(0)
        manifest, compose_file = source.manifest, source.compose_file

    backup_conf = manifest.get("backup", {})
    backup_type = backup_conf.get("type", "none")

    if backup_type == "none":
        print(f"{project_name}: no backup configured (type: none)")
        return BackupResult(0)

    dump_command = backup_conf.get("dump_command", "")
    if not dump_command:
        return _failed(f"backup type is '{backup_type}' but no dump_command defined")

    try:
        service = resolve_backup_service(manifest)
    except BackupError as e:
        return _failed(str(e))
    retention = (backup_conf.get("retention", 7) if kind is BackupKind.NIGHTLY
                 else SNAPSHOT_RETENTION[kind])
    problem = retention_problem(retention)
    if problem:
        return _failed(problem)
    key_path = paths.backup_key

    if not key_path.exists():
        return _failed(f"Backup encryption key not found: {key_path}")

    return _run_backup_inner(
        project_name, paths, dump_command, service, kind, retention, compose_file, offline,
    )


def _run_backup_inner(
    project_name: str,
    paths: BoxPaths,
    dump_command: str,
    service: str,
    kind: BackupKind,
    retention: int,
    compose_file: Path | None = None,
    offline: bool = False,
) -> BackupResult:
    print(f"{project_name}: starting {kind.value} backup (service: {service})...")
    sweep_stale_dumps(paths, project_name)

    try:
        raw_path = execute_dump(paths, project_name, dump_command, service, compose_file,
                                offline=offline)
    except BackupError as e:
        log_error("backup", f"Backup dump failed: {e}", paths, project=project_name)
        return _failed(str(e))

    fname = backup_filename(project_name, kind)
    published = paths.project_backups(project_name) / fname
    try:
        _backup.encrypt_file(raw_path, published, paths)
    except (BackupError, FileNotFoundError) as e:
        log_error("backup", f"Backup encrypt failed: {e}", paths, project=project_name)
        return _failed(f"Encryption failed: {e}")
    finally:
        raw_path.unlink(missing_ok=True)
    record_snapshot(paths, project_name, fname)

    pruned = prune_unpaired(paths, project_name, kind, retention, published=fname)
    if pruned:
        print(f"  Pruned {len(pruned)} old {kind.value} backup(s)")

    log_operation("backup", f"Backup completed: {fname}", paths, project=project_name)
    print(f"{project_name}: backup complete -> {fname}")
    return BackupResult(0, snapshot=published)


def _attempt_locked_backup(name: str, paths: BoxPaths) -> BackupAttemptResult:
    """Attempt a single backup under the project lock (audit I-NEW-2).

    Returns:
      - ``BackupAttemptResult.OK``     — backup succeeded (rc 0)
      - ``BackupAttemptResult.FAILED`` — backup ran but returned non-zero
      - ``BackupAttemptResult.LOCKED`` — project lock was held by another op
    """
    try:
        with project_lock(name, paths):
            result = snapshot_locked(name, paths, kind=BackupKind.NIGHTLY)
    except LockError:
        return BackupAttemptResult.LOCKED
    if result.rc != 0:
        record_failure(paths, name, str(result.cause))
        return BackupAttemptResult.FAILED
    if result.snapshot is None and result.cause is None:
        record_excused(paths, name)   # none was due; a skip (cause) is not excused
    return BackupAttemptResult.OK


def _attempt_isolated(name: str, paths: BoxPaths) -> BackupAttemptResult:
    """_attempt_locked_backup for a fleet loop: a project whose inputs cannot
    be read is reported and FAILED, so the loop reaches every other project
    and its retries and lock alert still run."""
    try:
        return _attempt_locked_backup(name, paths)
    except PROJECT_INPUT_ERRORS as e:
        report_project_failure("backup-all", name, e, paths)
        record_failure(paths, name, str(e))
        return BackupAttemptResult.FAILED


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
    # only printed (preserved). A rightly skipped night is not a missed one.
    for name in projects:
        try:
            block = is_blocked(name, paths)
            if block and block.reason is BlockReason.PAUSED:
                print(f"  Skipping {name}: paused.")
                record_excused(paths, name)
                continue
            if block and block.reason is BlockReason.MIGRATING:
                print(f"  Skipping {name}: {block.skip_message}.")
                log_operation("backup", block.skip_message, paths, project=name)
                record_excused(paths, name)
                continue
            if block and block.reason is BlockReason.QUARANTINED:
                print(f"  Skipping {name}: CVE-quarantined.")
                log_operation(
                    "backup", block.skip_message,
                    paths, project=name,
                )
                record_excused(paths, name)
                continue
        except PROJECT_INPUT_ERRORS as e:
            report_project_failure("backup-all", name, e, paths)
            record_failure(paths, name, str(e))
            failed.append(name)
            continue
        result = _attempt_isolated(name, paths)
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
                outcome = _attempt_isolated(name, paths)
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

    # Tell the operator of each failure above (and anything still undelivered).
    deliver(paths, notify)
    if failed or locked:
        return 1
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
