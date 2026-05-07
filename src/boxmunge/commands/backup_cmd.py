"""boxmunge backup/backup-all/backup-sync commands."""

import enum
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import boxmunge.backup as _backup
from boxmunge.backup import backup_filename, prune_backups, BackupError
from boxmunge.config import load_config, ConfigError
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.fileutil import project_lock, LockError
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.pause import is_paused
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


def _execute_dump(
    project_dir: Path, dump_command: str, project_name: str, service: str,
) -> Path:
    """Run the dump command inside the project container and capture output."""
    backups_dir = project_dir / "backups"
    backups_dir.mkdir(parents=True, exist_ok=True)
    fd, raw_path_str = tempfile.mkstemp(
        dir=backups_dir, prefix=".dump-", suffix=".tar.gz"
    )
    os.close(fd)
    raw_path = Path(raw_path_str)

    cmd = [
        "docker", "compose",
        "-f", "compose.yml",
        "-p", project_name,
        "exec", "-T", service,
        "sh", "-c", dump_command,
    ]

    with open(raw_path, "wb") as outf:
        result = subprocess.run(
            cmd, cwd=project_dir,
            stdout=outf, stderr=subprocess.PIPE, text=False,
        )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
        raw_path.unlink(missing_ok=True)
        raise BackupError(f"Dump command failed: {stderr}")

    return raw_path


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


def run_backup(project_name: str, paths: BoxPaths, _lock_held: bool = False) -> int:
    """Run backup for a project. Returns 0 on success, 1 on failure."""
    if is_paused(project_name, paths):
        print(
            f"ERROR: Project '{project_name}' is paused. Resume first.",
            file=sys.stderr,
        )
        return 1
    # Wave 1: backups of stopped (CVE-quarantined) services are pointless
    # and would emit confusing "volume empty" warnings — skip cleanly with
    # a structured log entry, returning 0 (no broader operation to fail).
    if is_quarantined(project_name, paths):
        print(
            f"{project_name}: skipping backup — CVE-quarantined "
            f"(use `boxmunge security resume` to lift)",
        )
        log_operation(
            "backup",
            f"Skipped quarantined project '{project_name}' — use "
            f"`boxmunge security resume` to lift",
            paths, project=project_name,
        )
        return 0
    clear_probation_if_active(paths, "backup")
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists():
        print(f"ERROR: Project not found: {project_name}", file=sys.stderr)
        return 1

    if paths.is_project_pre_registered(project_name):
        print(f"ERROR: Project '{project_name}' is pre-registered (secrets set) but "
              f"not yet deployed. Deploy first with: boxmunge deploy {project_name}", file=sys.stderr)
        return 1

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

    service = backup_conf.get("service", "web")
    retention = backup_conf.get("retention", 7)
    key_path = paths.backup_key

    if not key_path.exists():
        print(f"ERROR: Backup encryption key not found: {key_path}", file=sys.stderr)
        return 1

    if not _lock_held:
        try:
            with project_lock(project_name, paths):
                return _run_backup_inner(
                    project_name, paths, project_dir, dump_command, service, retention, key_path,
                )
        except LockError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
    return _run_backup_inner(
        project_name, paths, project_dir, dump_command, service, retention, key_path,
    )


def _run_backup_inner(
    project_name: str,
    paths: BoxPaths,
    project_dir: Any,
    dump_command: str,
    service: str,
    retention: int,
    key_path: Any,
) -> int:
    print(f"{project_name}: starting backup (service: {service})...")

    try:
        raw_path = _execute_dump(project_dir, dump_command, project_name, service)
    except BackupError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        log_error("backup", f"Backup dump failed: {e}", paths, project=project_name)
        return 1

    fname = backup_filename(project_name)
    encrypted_path = paths.project_backups(project_name) / fname
    encrypted_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        _backup.encrypt_file(raw_path, encrypted_path, key_path)
    except (BackupError, FileNotFoundError) as e:
        print(f"ERROR: Encryption failed: {e}", file=sys.stderr)
        raw_path.unlink(missing_ok=True)
        log_error("backup", f"Backup encrypt failed: {e}", paths, project=project_name)
        return 1
    finally:
        raw_path.unlink(missing_ok=True)

    pruned = prune_backups(paths.project_backups(project_name), project_name, retention)
    if pruned:
        print(f"  Pruned {len(pruned)} old backup(s)")

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
            rc = run_backup(name, paths, _lock_held=True)
    except LockError:
        return BackupAttemptResult.LOCKED
    return BackupAttemptResult.OK if rc == 0 else BackupAttemptResult.FAILED


def _notify_persistent_locks(paths: BoxPaths, locked: list[str]) -> None:
    """Send a Pushover alert for projects that remained locked through retries.

    Without this, a deploy started just before 02:00 silently consumes its
    project's nightly backup window with no operator-visible signal. Pushover
    is the operator's only out-of-band channel; failures here must surface
    in the log.

    Audit D-NEW-3: send_notification returns False when Pushover keys are
    empty. Without surfacing that, the operator can't tell "alert sent" from
    "alert silently dropped". Both branches now leave a forensic trail.
    """
    if not locked:
        return
    try:
        from boxmunge.pushover import send_notification
        cfg = load_config(paths)
        po = cfg.get("pushover", {})
        names = ", ".join(locked)
        sent = send_notification(
            po.get("user_key", ""), po.get("app_token", ""),
            "boxmunge backup-all SKIPPED (locked)",
            f"Backup skipped for projects: {names}. They were locked at backup "
            f"time and remained locked through retries — likely a stuck deploy "
            f"or a long-running maintenance op.",
        )
    except (ConfigError, OSError) as e:
        log_error(
            "backup", f"Pushover lock-skip alert failed: {e}", paths,
            detail={"locked": locked},
        )
        return

    if sent:
        log_operation(
            "backup",
            f"Pushover sent for {len(locked)} persistent locks",
            paths, detail={"locked": locked},
        )
    else:
        log_warning(
            "backup",
            f"persistent backup locks ({len(locked)}); "
            "Pushover not configured — alert dropped",
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

    # First pass: try every non-paused, non-quarantined project once.
    for name in projects:
        if is_paused(name, paths):
            print(f"  Skipping {name}: paused.")
            continue
        if is_quarantined(name, paths):
            print(f"  Skipping {name}: CVE-quarantined.")
            log_operation(
                "backup",
                f"Skipped quarantined project '{name}' — use "
                f"`boxmunge security resume` to lift",
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
    """Sync encrypted backups to the configured remote via rclone."""
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
        container_src = f"/projects/{project_name}/backups/"
        dest = f"{remote}/{project_name}/"
    else:
        container_src = "/projects/"
        dest = remote

    print(f"Syncing backups to {dest}...")

    from boxmunge.system_container import system_exec, ensure_system_container, SystemContainerError

    rclone_cmd = ["rclone", "sync", container_src, dest,
                  "--include", "*.tar.gz.age",
                  "--config", "/config/rclone.conf"]

    if ensure_system_container():
        try:
            system_exec(rclone_cmd)
        except SystemContainerError as e:
            print(f"ERROR: rclone sync failed: {e}", file=sys.stderr)
            return 1
    else:
        # Fallback: host-level rclone
        host_src = str(paths.project_backups(project_name)) if project_name else str(paths.projects)
        try:
            subprocess.run(
                ["rclone", "sync", host_src, dest, "--include", "*.tar.gz.age"],
                check=True, capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"ERROR: rclone sync failed: {e.stderr}", file=sys.stderr)
            return 1
        except FileNotFoundError:
            print("ERROR: rclone not found — install rclone or start the system container", file=sys.stderr)
            return 1

    log_operation("backup", f"Backup sync to {dest} completed", paths)
    print("Backup sync complete.")
    return 0


def cmd_backup(args: list[str]) -> None:
    if not args:
        print("Usage: boxmunge backup <project>", file=sys.stderr)
        sys.exit(2)

    from boxmunge.paths import validate_project_name
    try:
        validate_project_name(args[0])
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    paths = BoxPaths()
    sys.exit(run_backup(args[0], paths))


def cmd_backup_all(args: list[str]) -> None:
    paths = BoxPaths()
    sys.exit(run_backup_all(paths))


def cmd_backup_sync(args: list[str]) -> None:
    paths = BoxPaths()
    project = args[0] if args else None
    sys.exit(run_backup_sync(paths, project))
