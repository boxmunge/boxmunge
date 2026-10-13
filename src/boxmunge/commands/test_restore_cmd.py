"""boxmunge test-restore <project> — verify the latest backup decrypts."""

import sys

from boxmunge.backup import decrypted_snapshot, BackupError
from boxmunge.commands.backup_cmd import list_snapshots
from boxmunge.log import log_operation
from boxmunge.paths import BoxPaths


def run_test_restore(project_name: str, paths: BoxPaths) -> int:
    """Test that the most recent backup can be decrypted.

    Does NOT actually restore data — just verifies the archive decrypts. The
    project's restore_command is never run, so this does not prove an
    end-to-end restore.
    Returns 0 if the backup decrypts successfully, 1 on failure.
    """
    snapshots = list_snapshots(paths, project_name)
    if not snapshots:
        print(f"ERROR: No backup snapshots found for {project_name}", file=sys.stderr)
        return 1

    snapshot = snapshots[0]
    key_path = paths.backup_key
    if not key_path.exists():
        print(f"ERROR: Backup key not found: {key_path}", file=sys.stderr)
        return 1

    print(f"Testing restore of {snapshot.name}...")

    try:
        with decrypted_snapshot(snapshot, key_path) as output:
            size = output.stat().st_size if output.exists() else 0
    except (BackupError, FileNotFoundError) as e:
        print(f"FAIL: Decryption failed: {e}")
        return 1

    if size == 0:
        print("FAIL: Decrypted output is empty")
        return 1
    print(f"PASS: Backup decrypts successfully ({size} bytes)")
    log_operation("test-restore", f"Test-restore passed: {snapshot.name}", paths, project=project_name)
    return 0


def cmd_test_restore(args: list[str]) -> None:
    """CLI entry point."""
    from boxmunge.commands.argv import parse_args, require_project_name
    parsed = parse_args("test-restore", args, min_positional=1, max_positional=1)
    project = require_project_name("test-restore", parsed.positional[0])
    paths = BoxPaths()
    sys.exit(run_test_restore(project, paths))
