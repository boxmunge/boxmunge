"""boxmunge backup/backup-all/backup-sync commands."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import boxmunge.backup as _backup
from boxmunge.backup import backup_filename, prune_backups, BackupError
from boxmunge.config import load_config, ConfigError
from boxmunge.fileutil import project_lock, LockError
from boxmunge.log import log_operation, log_error
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.probation import clear_probation_if_active


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
    clear_probation_if_active(paths, "backup")
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists():
        print(f"ERROR: Project not found: {project_name}")
        return 1

    if paths.is_project_pre_registered(project_name):
        print(f"ERROR: Project '{project_name}' is pre-registered (secrets set) but "
              f"not yet deployed. Deploy first with: boxmunge deploy {project_name}")
        return 1

    try:
        manifest = load_manifest(paths.project_manifest(project_name))
    except ManifestError as e:
        print(f"ERROR: {e}")
        return 1

    backup_conf = manifest.get("backup", {})
    backup_type = backup_conf.get("type", "none")

    if backup_type == "none":
        print(f"{project_name}: no backup configured (type: none)")
        return 0

    dump_command = backup_conf.get("dump_command", "")
    if not dump_command:
        print(f"ERROR: backup type is '{backup_type}' but no dump_command defined")
        return 1

    service = backup_conf.get("service", "web")
    retention = backup_conf.get("retention", 7)
    key_path = paths.backup_key

    if not key_path.exists():
        print(f"ERROR: Backup encryption key not found: {key_path}")
        return 1

    if not _lock_held:
        try:
            with project_lock(project_name, paths):
                return _run_backup_inner(
                    project_name, paths, project_dir, dump_command, service, retention, key_path,
                )
        except LockError as e:
            print(f"ERROR: {e}")
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
        print(f"ERROR: {e}")
        log_error("backup", f"Backup dump failed: {e}", paths, project=project_name)
        return 1

    fname = backup_filename(project_name)
    encrypted_path = paths.project_backups(project_name) / fname
    encrypted_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        _backup.encrypt_file(raw_path, encrypted_path, key_path)
    except (BackupError, FileNotFoundError) as e:
        print(f"ERROR: Encryption failed: {e}")
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


def run_backup_all(paths: BoxPaths) -> int:
    """Backup all projects that have backup configured."""
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

    worst = 0
    for name in projects:
        result = run_backup(name, paths)
        worst = max(worst, result)

    return worst


def run_backup_sync(paths: BoxPaths, project_name: str | None = None) -> int:
    """Sync encrypted backups to the configured remote via rclone."""
    try:
        config = load_config(paths)
    except ConfigError as e:
        print(f"ERROR: {e}")
        return 1

    remote = config.get("backup_remote", "")
    if not remote:
        print("ERROR: backup_remote not configured in boxmunge.yml")
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
            print(f"ERROR: rclone sync failed: {e}")
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
            print(f"ERROR: rclone sync failed: {e.stderr}")
            return 1
        except FileNotFoundError:
            print("ERROR: rclone not found — install rclone or start the system container")
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
