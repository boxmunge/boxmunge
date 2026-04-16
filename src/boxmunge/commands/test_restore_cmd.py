"""boxmunge test-restore <project> — verify a backup can be restored."""

import sys
import tempfile
from pathlib import Path

from boxmunge.backup import decrypt_file, BackupError
from boxmunge.commands.backup_cmd import list_snapshots
from boxmunge.log import log_operation
from boxmunge.paths import BoxPaths


def run_test_restore(project_name: str, paths: BoxPaths) -> int:
    """Test that the most recent backup can be decrypted.

    Does NOT actually restore data — just verifies the archive is valid.
    Returns 0 if the backup decrypts successfully, 1 on failure.
    """
    snapshots = list_snapshots(paths, project_name)
    if not snapshots:
        print(f"ERROR: No backup snapshots found for {project_name}")
        return 1

    snapshot = snapshots[0]
    key_path = paths.backup_key
    if not key_path.exists():
        print(f"ERROR: Backup key not found: {key_path}")
        return 1

    print(f"Testing restore of {snapshot.name}...")

    with tempfile.TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "test-restore.tar.gz"
        try:
            decrypt_file(snapshot, output, key_path)
        except (BackupError, FileNotFoundError) as e:
            print(f"FAIL: Decryption failed: {e}")
            return 1

        if output.exists() and output.stat().st_size > 0:
            print(f"PASS: Backup decrypts successfully ({output.stat().st_size} bytes)")
            log_operation("test-restore", f"Test-restore passed: {snapshot.name}", paths, project=project_name)
            return 0
        else:
            print(f"FAIL: Decrypted output is empty")
            return 1


def cmd_test_restore(args: list[str]) -> None:
    """CLI entry point."""
    if not args:
        print("Usage: boxmunge test-restore <project>", file=sys.stderr)
        sys.exit(2)
    paths = BoxPaths()
    sys.exit(run_test_restore(args[0], paths))
