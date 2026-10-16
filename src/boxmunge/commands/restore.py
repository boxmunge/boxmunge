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
"""

import os
import subprocess
import sys
import time
from pathlib import Path

from boxmunge.backup import (
    SNAPSHOT_RETENTION, BackupError, BackupKind, decrypted_snapshot, prune_backups,
    resolve_backup_service,
)
from boxmunge.commands.backup_cmd import list_snapshots, sweep_stale_dumps
from boxmunge.docker import compose_command, compose_down, compose_up, DockerError
from boxmunge.docker_run import docker_env
from boxmunge.fileutil import LockError, open_regular_nofollow, project_lock
from boxmunge.lifecycle import is_blocked
from boxmunge.log import log_operation, log_error
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.probation import clear_probation_if_active
from boxmunge.restore_safety import RestoreError, take_safety_snapshot, verify_plaintext
from boxmunge.service_exec import ServiceCommandTimeout, run_in_service

RESTORE_COMMAND_TIMEOUT = 600  # seconds; matches the backup dump budget
_SERVICE_START_TIMEOUT = 120
_READY_ATTEMPTS = 30
_READY_INTERVAL = 1.0
_NO_HEALTHCHECK_GRACE = 2.0


def run_restore(
    project_name: str,
    paths: BoxPaths,
    snapshot: str | None = None,
    yes: bool = False,
    _lock_held: bool = False,
    safety_snapshot: bool = True,
) -> int:
    """Restore a project from a backup snapshot. Returns 0 on success, 1 on failure."""
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists():
        print(f"ERROR: Project not found: {project_name}", file=sys.stderr)
        return 1

    try:
        manifest = load_manifest(paths.project_manifest(project_name))
    except ManifestError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    backup_conf = manifest.get("backup", {})
    if not backup_conf:
        print(
            f"ERROR: No backup configuration found in manifest for "
            f"{project_name} — restore requires `backup.service` and "
            f"`backup.restore_command`.",
            file=sys.stderr,
        )
        return 1
    try:
        service = resolve_backup_service(manifest)
    except BackupError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    restore_command = backup_conf.get("restore_command", "")
    if not restore_command:
        print(
            f"ERROR: backup.restore_command is missing from manifest for "
            f"{project_name}.",
            file=sys.stderr,
        )
        return 1

    snapshot_path = _choose_snapshot(paths, project_name, snapshot)
    if snapshot_path is None:
        return 1

    if not yes:
        print(f"\nWill restore {project_name} from {snapshot_path.name}")
        print("This will STOP the project and overwrite current data.")
        response = input("Proceed? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            return 1

    key_path = paths.backup_key
    if not key_path.exists():
        print(f"ERROR: Backup key not found: {key_path}", file=sys.stderr)
        return 1

    def inner() -> int:
        sweep_stale_dumps(paths, project_name)
        # Checked under the lock: restore is operator-initiated and mutates
        # compose state. REFUSE if the project is paused or CVE-quarantined
        # — the operator must explicitly resume / security-resume first.
        block = is_blocked(project_name, paths)
        if block:
            print(f"ERROR: {block.refuse_message}", file=sys.stderr)
            return 1
        clear_probation_if_active(paths, "restore")
        return _run_restore_inner(
            project_name, paths, snapshot_path, service, restore_command,
            backup_conf.get("dump_command", "") if safety_snapshot else None,
        )

    if _lock_held:
        return inner()
    try:
        with project_lock(project_name, paths):
            return inner()
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


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
                safety = take_safety_snapshot(project_name, paths, dump_command, service)
                print(f"  Safety snapshot: {safety.name}")
            phase = "replace"
            rc = _replace_data(project_name, paths, service, restore_command,
                               plaintext, snapshot_path, safety)
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
) -> int:
    """Stop, restore, and always start the project again."""
    project_dir = paths.project_dir(project_name)
    compose_files = _compose_files(paths, project_name)
    restored = False
    try:
        print("  Stopping project...")
        try:
            compose_down(project_dir, compose_files=compose_files,
                         project_name=project_name)
        except DockerError as e:
            print(f"  WARN: Stop failed (may not be running): {e}")
        print(f"  Starting {service} for restore...")
        _start_service(project_dir, compose_files, project_name, service)
        _wait_ready(project_name, service)
        print("  Restoring data...")
        _run_restore_command(project_dir, project_name, service, restore_command, plaintext)
        restored = True
    except (DockerError, RestoreError, OSError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"  ERROR: {e}", file=sys.stderr)
        log_error("restore", f"Restore failed: {e}", paths, project=project_name)
    finally:
        print("  Starting all services..." if restored
              else "  Restarting all services...")
        started = _start_all(project_dir, compose_files, project_name)

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
    return 0


def _start_service(
    project_dir: Path, compose_files: list[str], project_name: str, service: str,
) -> None:
    cmd = compose_command(project_name, compose_files)
    cmd.extend(["up", "-d", service])
    subprocess.run(cmd, cwd=project_dir, check=True, capture_output=True,
                   text=True, timeout=_SERVICE_START_TIMEOUT, env=docker_env())


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


def _start_all(project_dir: Path, compose_files: list[str], project_name: str) -> bool:
    """Start every service. The backup service is still running from the
    restore and may hold the pre-restore data open or in memory, so it is
    recreated rather than left as it is."""
    try:
        compose_up(project_dir, compose_files=compose_files,
                   project_name=project_name, force_recreate=True)
    except DockerError as e:
        print(f"  ERROR: Start failed: {e}", file=sys.stderr)
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
