"""boxmunge restore <project> [snapshot] — restore from backup."""

import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from boxmunge.backup import decrypt_file, BackupError
from boxmunge.commands.backup_cmd import list_snapshots
from boxmunge.docker import compose_down, compose_up, DockerError
from boxmunge.fileutil import project_lock, LockError
from boxmunge.log import log_operation, log_error
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.paths import BoxPaths


def _restore_snapshot(
    snapshot_path: Path, project_dir: Path, key_path: Path,
    restore_command: str, project_name: str, service: str,
) -> bool:
    """Decrypt snapshot into a temp directory and run the restore command."""
    with tempfile.TemporaryDirectory() as tmpdir:
        decrypted = Path(tmpdir) / snapshot_path.stem  # strips .age, lands in tmpdir
        try:
            decrypt_file(snapshot_path, decrypted, key_path)

            cmd = [
                "docker", "compose",
                "-f", "compose.yml",
                "-p", project_name,
                "exec", "-T", service,
                "sh", "-c", restore_command,
            ]

            with open(decrypted, "rb") as inf:
                result = subprocess.run(
                    cmd, cwd=project_dir,
                    stdin=inf, capture_output=True, text=True,
                )
            if result.returncode != 0:
                print(f"  ERROR: Restore command failed: {result.stderr}")
                return False
        except (BackupError, FileNotFoundError) as e:
            print(f"  ERROR: Decryption failed: {e}")
            return False

    return True


def run_restore(
    project_name: str,
    paths: BoxPaths,
    snapshot: str | None = None,
    yes: bool = False,
    _lock_held: bool = False,
) -> int:
    """Restore a project from a backup snapshot. Returns 0 on success, 1 on failure."""
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists():
        print(f"ERROR: Project not found: {project_name}")
        return 1

    try:
        manifest = load_manifest(paths.project_manifest(project_name))
    except ManifestError as e:
        print(f"ERROR: {e}")
        return 1

    backup_conf = manifest.get("backup", {})
    service = backup_conf.get("service", "web")
    restore_command = backup_conf.get("restore_command", "")
    if not restore_command:
        print(f"ERROR: No restore_command configured for {project_name}")
        return 1

    snapshots = list_snapshots(paths, project_name)
    if not snapshots:
        print(f"ERROR: No backup snapshots found for {project_name}")
        return 1

    if snapshot:
        snapshot_path = paths.project_backups(project_name) / snapshot
        # Prevent path traversal
        resolved = snapshot_path.resolve()
        expected_root = paths.project_backups(project_name).resolve()
        if not str(resolved).startswith(str(expected_root) + "/"):
            print("ERROR: Invalid snapshot path (path traversal detected)")
            return 1
        if not snapshot_path.exists():
            print(f"ERROR: Snapshot not found: {snapshot}")
            return 1
    else:
        print(f"Available snapshots for {project_name}:")
        for i, s in enumerate(snapshots):
            print(f"  [{i+1}] {s.name}")
        snapshot_path = snapshots[0]
        print(f"\nUsing most recent: {snapshot_path.name}")

    if not yes:
        print(f"\nWill restore {project_name} from {snapshot_path.name}")
        print("This will STOP the project and overwrite current data.")
        response = input("Proceed? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            return 1

    key_path = paths.backup_key
    if not key_path.exists():
        print(f"ERROR: Backup key not found: {key_path}")
        return 1

    if _lock_held:
        return _run_restore_inner(project_name, paths, snapshot_path, service, restore_command,
                                  project_dir, key_path)

    try:
        with project_lock(project_name, paths):
            return _run_restore_inner(project_name, paths, snapshot_path, service, restore_command,
                                      project_dir, key_path)
    except LockError as e:
        print(f"ERROR: {e}")
        return 1


def _run_restore_inner(
    project_name: str,
    paths: BoxPaths,
    snapshot_path: Path,
    service: str,
    restore_command: str,
    project_dir: Path,
    key_path: Path,
) -> int:
    print(f"Restoring {project_name} from {snapshot_path.name}...")

    print("  Stopping project...")
    compose_files = ["compose.yml"]
    override = paths.project_compose_override(project_name)
    if override.exists():
        compose_files.append("compose.boxmunge.yml")
    try:
        compose_down(project_dir, compose_files=compose_files)
    except DockerError as e:
        print(f"  WARN: Stop failed (may not be running): {e}")

    # Start only the backup service (e.g. db) so restore can exec into it
    print(f"  Starting {service} for restore...")
    try:
        cmd = ["docker", "compose"]
        for f in compose_files:
            cmd.extend(["-f", f])
        cmd.extend(["up", "-d", service])
        subprocess.run(cmd, cwd=project_dir, check=True,
                       capture_output=True, text=True, timeout=120)
        # Wait for the service to be healthy (respects Docker healthcheck)
        container_name = f"{project_name}-{service}-1"
        for _ in range(30):
            health = subprocess.run(
                ["docker", "inspect", "--format",
                 "{{.State.Health.Status}}", container_name],
                capture_output=True, text=True, check=False, timeout=10,
            )
            status = health.stdout.strip()
            if status == "healthy":
                break
            if health.returncode != 0:
                # No healthcheck defined — just check container is running
                state = subprocess.run(
                    ["docker", "inspect", "--format",
                     "{{.State.Status}}", container_name],
                    capture_output=True, text=True, check=False, timeout=10,
                )
                if state.stdout.strip() == "running":
                    time.sleep(2)  # Grace period for services without healthcheck
                    break
            time.sleep(1)
    except (DockerError, subprocess.CalledProcessError) as e:
        print(f"  ERROR: Could not start {service} for restore: {e}")
        return 1

    print("  Decrypting and restoring...")
    if not _restore_snapshot(
        snapshot_path, project_dir, key_path, restore_command,
        project_name, service,
    ):
        log_error("restore", "Restore failed", paths, project=project_name)
        return 1

    print("  Starting all services...")
    try:
        compose_up(project_dir, compose_files=compose_files)
    except DockerError as e:
        print(f"  ERROR: Start failed: {e}")
        return 1

    log_operation("restore", f"Restored from {snapshot_path.name}", paths, project=project_name)
    print(f"{project_name}: restore complete")
    return 0


def cmd_restore(args: list[str]) -> None:
    if not args:
        print("Usage: boxmunge restore <project> [snapshot] [--yes]", file=sys.stderr)
        sys.exit(2)

    project = args[0]

    from boxmunge.paths import validate_project_name
    try:
        validate_project_name(project)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    snapshot = None
    yes = "--yes" in args

    for arg in args[1:]:
        if not arg.startswith("--"):
            snapshot = arg
            break

    paths = BoxPaths()
    sys.exit(run_restore(project, paths, snapshot=snapshot, yes=yes))
