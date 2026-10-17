"""boxmunge restore <project> [snapshot] — restore from backup.

Order of work, all under the project lock (audit C-09):

1. Decrypt the snapshot into a private temp dir under the project's
   backups/ (mounted into the system container, where age runs) and verify
   it unpacks. Production is still running.
2. Take a pre-restore safety snapshot of the current data (unless
   ``--no-safety-snapshot``). Production is still running.
3. Stop the project, start the backup service, wait until it is ready,
   and pipe the plaintext into ``restore_command`` (bounded by a timeout).
4. Start every service again, recreating the backup service so its
   process starts over on the restored data. This runs on every path out
   of step 3, success or failure, including timeouts and permission errors.

A project the health monitor stopped stays stopped: only the backup
service runs, for the safety snapshot and the restore, and every service
is stopped again afterwards. ``recover`` then starts it on the restored
data and runs the smoke test that clears the stop.
"""

import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from boxmunge.backup import (
    SNAPSHOT_RETENTION, BackupError, BackupKind, decrypted_snapshot, prune_backups,
    resolve_backup_service,
)
from boxmunge.commands.backup_cmd import list_snapshots, sweep_stale_dumps
from boxmunge.commands.health_state import is_monitor_stopped
from boxmunge.compose_guard import (
    ComposeRefused, check_start, compose_up_canary, compose_up_checked,
)
from boxmunge.docker import compose_down, DockerError
from boxmunge.docker_run import docker_env
from boxmunge.fileutil import LockError, open_regular_nofollow, project_lock
from boxmunge.lifecycle import refuse_if_blocked
from boxmunge.legacy_stage import refuse_if_legacy_stage
from boxmunge.log import log_operation, log_error
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.probation import clear_probation_if_active
from boxmunge.release_txn import refuse_if_install_open
from boxmunge.restore_safety import RestoreError, take_safety_snapshot, verify_plaintext
from boxmunge.service_exec import ServiceCommandTimeout, run_in_service

RESTORE_COMMAND_TIMEOUT = 600  # seconds; matches the backup dump budget
_READY_ATTEMPTS = 30
_READY_INTERVAL = 1.0
_NO_HEALTHCHECK_GRACE = 2.0


@dataclass(frozen=True)
class _RestorePlan:
    snapshot_path: Path
    service: str
    restore_command: str
    dump_command: str


def _restore_plan(project_name: str, paths: BoxPaths,
                  snapshot: str | None) -> _RestorePlan | None:
    """What a restore would do, from the manifest on disk. None (after
    printing why) if it cannot."""
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists():
        print(f"ERROR: Project not found: {project_name}", file=sys.stderr)
        return None

    try:
        manifest = load_manifest(paths.project_manifest(project_name))
    except ManifestError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return None

    backup_conf = manifest.get("backup", {})
    if not backup_conf:
        print(
            f"ERROR: No backup configuration found in manifest for "
            f"{project_name} — restore requires `backup.service` and "
            f"`backup.restore_command`.",
            file=sys.stderr,
        )
        return None
    try:
        service = resolve_backup_service(manifest)
    except BackupError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return None
    restore_command = backup_conf.get("restore_command", "")
    if not restore_command:
        print(
            f"ERROR: backup.restore_command is missing from manifest for "
            f"{project_name}.",
            file=sys.stderr,
        )
        return None

    snapshot_path = _choose_snapshot(paths, project_name, snapshot)
    if snapshot_path is None:
        return None
    if not paths.backup_key.exists():
        print(f"ERROR: Backup key not found: {paths.backup_key}", file=sys.stderr)
        return None
    return _RestorePlan(snapshot_path, service, restore_command,
                        backup_conf.get("dump_command", ""))


def run_restore(
    project_name: str,
    paths: BoxPaths,
    snapshot: str | None = None,
    yes: bool = False,
    safety_snapshot: bool = True,
    canary: bool = False,
) -> int:
    """restore: confirm, take the project lock and restore. Returns 0 on
    success, 1 on failure.

    `canary` is for `self-test` alone: its canary is boxmunge's own fixture,
    started without the project checks (see compose_guard.compose_up_canary)."""
    if refuse_if_install_open(paths, project_name, component="restore"):
        return 1   # before the prompt; restore_locked checks again under the lock
    plan = _restore_plan(project_name, paths, snapshot)
    if plan is None:
        return 1

    if not yes:
        print(f"\nWill restore {project_name} from {plan.snapshot_path.name}")
        print("This will STOP the project and overwrite current data.")
        response = input("Proceed? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            return 1

    try:
        with project_lock(project_name, paths):
            # The snapshot the operator confirmed, not whatever is newest now.
            return restore_locked(project_name, paths, plan.snapshot_path.name,
                                  safety_snapshot, canary=canary)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def restore_locked(project_name: str, paths: BoxPaths, snapshot: str | None,
                   safety_snapshot: bool = True, canary: bool = False,
                   txn: str | None = None) -> int:
    """The restore core. Caller holds the project lock; never takes it.

    Refuses a paused or CVE-quarantined project — the operator must resume
    or security-resume first — and, before anything is stopped, a project
    with an open install transaction other than `txn` (the rollback that
    restores as part of its own transaction). Reads the backup config,
    checked under the lock immediately before production is touched. A
    project the health monitor stopped gets its data back but is left
    stopped, for `recover`.
    """
    if refuse_if_legacy_stage(paths, project_name):
        return 1
    sweep_stale_dumps(paths, project_name)
    if refuse_if_blocked(project_name, paths):
        return 1
    if refuse_if_install_open(paths, project_name, component="restore", txn=txn):
        return 1
    plan = _restore_plan(project_name, paths, snapshot)
    if plan is None:
        return 1
    clear_probation_if_active(paths, "restore")
    leave_stopped = is_monitor_stopped(project_name, paths)
    if leave_stopped:
        print(f"  '{project_name}' was stopped by the health monitor: only "
              f"{plan.service} is started for the restore, and it stays stopped.")
    return _run_restore_inner(
        project_name, paths, plan.snapshot_path, plan.service,
        plan.restore_command, plan.dump_command if safety_snapshot else None,
        leave_stopped, canary, txn,
    )


def _choose_snapshot(paths: BoxPaths, project_name: str, snapshot: str | None) -> Path | None:
    snapshots = list_snapshots(paths, project_name)
    if not snapshots:
        print(f"ERROR: No backup snapshots found for {project_name}", file=sys.stderr)
        return None
    if not snapshot:
        print(f"Available snapshots for {project_name}:")
        for i, s in enumerate(snapshots):
            print(f"  [{i+1}] {s.name}")
        print(f"\nUsing most recent: {snapshots[0].name}")
        return snapshots[0]
    snapshot_path = paths.project_backups(project_name) / snapshot
    # Prevent path traversal
    resolved = snapshot_path.resolve()
    expected_root = paths.project_backups(project_name).resolve()
    if not str(resolved).startswith(str(expected_root) + "/"):
        print("ERROR: Invalid snapshot path (path traversal detected)", file=sys.stderr)
        return None
    if not snapshot_path.exists():
        print(f"ERROR: Snapshot not found: {snapshot}", file=sys.stderr)
        return None
    return snapshot_path


def _run_restore_inner(
    project_name: str,
    paths: BoxPaths,
    snapshot_path: Path,
    service: str,
    restore_command: str,
    dump_command: str | None,
    leave_stopped: bool,
    canary: bool = False,
    txn: str | None = None,
) -> int:
    """Verify, save, replace. Caller holds the project lock.

    ``dump_command`` None means no safety snapshot was requested.
    """
    print(f"Restoring {project_name} from {snapshot_path.name}...")
    phase = "verify"
    try:
        with decrypted_snapshot(snapshot_path, paths) as plaintext:
            print("  Decrypting and verifying snapshot...")
            verify_plaintext(plaintext)
            safety: Path | None = None
            if dump_command is not None:
                print("  Taking pre-restore safety snapshot...")
                safety = _safety_snapshot(project_name, paths, dump_command, service,
                                          leave_stopped, canary, txn)
                print(f"  Safety snapshot: {safety.name}")
            phase = "replace"
            rc = _replace_data(project_name, paths, service, restore_command,
                               plaintext, snapshot_path, safety, leave_stopped, canary, txn)
            phase = "cleanup"
    except (BackupError, RestoreError, OSError, subprocess.TimeoutExpired) as e:
        if phase == "verify":
            print(f"ERROR: {e}", file=sys.stderr)
            print("  Production was not touched.", file=sys.stderr)
            log_error("restore", f"Restore aborted before stopping the project: {e}",
                      paths, project=project_name)
            return 1
        if phase == "cleanup":
            print(f"ERROR: could not remove the decrypted snapshot copy: {e}",
                  file=sys.stderr)
            log_error("restore", f"Decrypted snapshot left on disk: {e}",
                      paths, project=project_name)
            return 1
        raise
    return rc


def _safety_snapshot(project_name: str, paths: BoxPaths, dump_command: str,
                     service: str, stopped: bool, canary: bool = False,
                     txn: str | None = None) -> Path:
    """Dump the current data. The monitor removed a stopped project's
    containers, so the backup service is started for the dump, and stopped
    again if the dump does not happen."""
    if not stopped:
        return take_safety_snapshot(project_name, paths, dump_command, service)
    project_dir = paths.project_dir(project_name)
    compose_files = _compose_files(paths, project_name)
    try:
        _start_service(paths, project_name, compose_files, service, canary, txn)
        _wait_ready(project_name, service)
        return take_safety_snapshot(project_name, paths, dump_command, service)
    except subprocess.CalledProcessError as e:
        _stop_all(project_dir, compose_files, project_name)
        raise RestoreError(f"could not start {service} for the safety snapshot: "
                           f"{e.stderr or e}") from e
    except BaseException:
        _stop_all(project_dir, compose_files, project_name)
        raise


def _compose_files(paths: BoxPaths, project_name: str) -> list[str]:
    compose_files = ["compose.yml"]
    if paths.project_compose_override(project_name).exists():
        compose_files.append("compose.boxmunge.yml")
    return compose_files


def _replace_data(
    project_name: str,
    paths: BoxPaths,
    service: str,
    restore_command: str,
    plaintext: Path,
    snapshot_path: Path,
    safety: Path | None,
    leave_stopped: bool,
    canary: bool = False,
    txn: str | None = None,
) -> int:
    """Stop, restore, and always start the project again (or, if the health
    monitor stopped it, always stop it again)."""
    project_dir = paths.project_dir(project_name)
    compose_files = _compose_files(paths, project_name)
    # Checked before the stop: a project that may not be started again must
    # not be taken down.
    if not canary:
        try:
            check_start(paths, project_name, component="restore",
                        compose_files=compose_files, txn=txn)
        except ComposeRefused as e:
            print(f"  ERROR: {e}", file=sys.stderr)
            print("  Production was not touched.", file=sys.stderr)
            return 1
    restored = False
    try:
        print("  Stopping project...")
        try:
            compose_down(project_dir, compose_files=compose_files,
                         project_name=project_name)
        except DockerError as e:
            print(f"  WARN: Stop failed (may not be running): {e}")
        print(f"  Starting {service} for restore...")
        _start_service(paths, project_name, compose_files, service, canary, txn)
        _wait_ready(project_name, service)
        print("  Restoring data...")
        _run_restore_command(project_dir, project_name, service, restore_command, plaintext)
        restored = True
    except (DockerError, RestoreError, OSError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"  ERROR: {e}", file=sys.stderr)
        log_error("restore", f"Restore failed: {e}", paths, project=project_name)
    finally:
        if leave_stopped:
            print("  Stopping every service again...")
            started = _stop_all(project_dir, compose_files, project_name)
        else:
            print("  Starting all services..." if restored
                  else "  Restarting all services...")
            started = _start_all(paths, project_name, compose_files, canary, txn)

    if not restored:
        if safety is not None:
            print(
                f"  The data may be partly restored. The state from before this "
                f"restore is in {safety.name}:\n"
                f"    boxmunge restore {project_name} {safety.name}",
                file=sys.stderr,
            )
        return 1
    if not started:
        return 1
    log_operation("restore", f"Restored from {snapshot_path.name}", paths, project=project_name)
    prune_backups(
        paths.project_backups(project_name), project_name,
        BackupKind.PRERESTORE, SNAPSHOT_RETENTION[BackupKind.PRERESTORE],
    )
    print(f"{project_name}: restore complete")
    if leave_stopped:
        print(f"  It is still stopped by the health monitor: run 'recover "
              f"{project_name}' to start it on the restored data.")
    return 0


def _start_service(
    paths: BoxPaths, project_name: str, compose_files: list[str], service: str,
    canary: bool, txn: str | None = None,
) -> None:
    """Start one service for the restore, through the start checks (no
    rebuild, so the exact deployed image comes back)."""
    _up(paths, project_name, compose_files, canary, txn, build=False, services=[service])


def _wait_ready(project_name: str, service: str) -> None:
    """Wait until the backup service is healthy (or running, without a
    healthcheck). Raise RestoreError if it never gets there."""
    container = f"{project_name}-{service}-1"
    fmt = "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}"
    last = ""
    for _ in range(_READY_ATTEMPTS):
        result = subprocess.run(
            ["docker", "inspect", "--format", fmt, container],
            capture_output=True, text=True, check=False, timeout=10,
            env=docker_env(),
        )
        last = result.stdout.strip() or result.stderr.strip()
        state, _, health = last.partition(" ")
        if result.returncode == 0 and state == "running":
            if health == "healthy":
                return
            if health == "none":
                time.sleep(_NO_HEALTHCHECK_GRACE)
                return
        time.sleep(_READY_INTERVAL)
    raise RestoreError(
        f"{service} did not become ready for restore "
        f"(last state: {last or 'unknown'})"
    )


def _run_restore_command(
    project_dir: Path, project_name: str, service: str,
    restore_command: str, plaintext: Path,
) -> None:
    # No-follow: see verify_plaintext.
    with os.fdopen(open_regular_nofollow(plaintext, os.O_RDONLY), "rb") as inf:
        try:
            result = run_in_service(
                project_dir, project_name, service, restore_command,
                timeout=RESTORE_COMMAND_TIMEOUT, stdin=inf, capture_output=True, text=True,
            )
        except ServiceCommandTimeout as e:
            raise RestoreError(f"restore_command {e}") from e
    if result.returncode != 0:
        raise RestoreError(f"restore_command failed: {result.stderr.strip()}")


def _up(paths: BoxPaths, project_name: str, compose_files: list[str], canary: bool,
        txn: str | None = None, **kwargs) -> None:
    if canary:
        compose_up_canary(paths, project_name, compose_files=compose_files, **kwargs)
    else:
        compose_up_checked(paths, project_name, component="restore",
                           compose_files=compose_files, txn=txn, **kwargs)


def _start_all(paths: BoxPaths, project_name: str, compose_files: list[str],
               canary: bool, txn: str | None = None) -> bool:
    """Start every service. The backup service is still running from the
    restore and may hold the pre-restore data open or in memory, so it is
    recreated rather than left as it is."""
    try:
        _up(paths, project_name, compose_files, canary, txn, force_recreate=True)
    except DockerError as e:
        print(f"  ERROR: Start failed: {e}", file=sys.stderr)
        return False
    return True


def _stop_all(project_dir: Path, compose_files: list[str], project_name: str) -> bool:
    """Stop and remove every service, as the health monitor left them."""
    try:
        compose_down(project_dir, compose_files=compose_files,
                     project_name=project_name)
    except DockerError as e:
        print(f"  ERROR: Stopping the services failed: {e}", file=sys.stderr)
        return False
    return True


def cmd_restore(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name
    parsed = parse_args(
        "restore", args, flags={"--yes", "--no-safety-snapshot"},
        min_positional=1, max_positional=2,
    )
    project = require_project_name("restore", parsed.positional[0])
    snapshot = parsed.positional[1] if len(parsed.positional) > 1 else None
    yes = parsed.has("--yes")
    safety_snapshot = not parsed.has("--no-safety-snapshot")

    paths = BoxPaths()
    sys.exit(run_restore(project, paths, snapshot=snapshot, yes=yes,
                         safety_snapshot=safety_snapshot))
