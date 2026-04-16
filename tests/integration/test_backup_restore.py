"""Integration tests for backup/restore round-trip."""

import json
import os
import subprocess
import urllib.request

import pytest

from boxmunge.paths import BoxPaths


pytestmark = [pytest.mark.integration]


class TestBackupRestoreRoundTrip:
    def test_backup_creates_encrypted_archive(self, deployed_fixture) -> None:
        """Backup produces an age-encrypted archive."""
        paths, project_name, port, compose_project = deployed_fixture

        # Insert test data first
        req = urllib.request.Request(
            f"http://localhost:{port}/data", data=b"backup-test", method="POST",
        )
        urllib.request.urlopen(req)

        from boxmunge.commands.backup_cmd import run_backup
        result = run_backup(project_name, paths)
        assert result == 0

        backups_dir = paths.project_backups(project_name)
        archives = list(backups_dir.glob(f"{project_name}-*.tar.gz.age"))
        assert len(archives) >= 1

    def test_restore_recovers_data(self, deployed_fixture) -> None:
        """Insert -> backup -> wipe -> restore -> verify data recovered."""
        paths, project_name, port, compose_project = deployed_fixture
        project_dir = paths.project_dir(project_name)

        # Insert known data
        for i in range(5):
            req = urllib.request.Request(
                f"http://localhost:{port}/data",
                data=f"restore-test-{i}".encode(),
                method="POST",
            )
            urllib.request.urlopen(req)

        # Record count
        resp = urllib.request.urlopen(f"http://localhost:{port}/data")
        before_count = json.loads(resp.read())["count"]
        assert before_count >= 5

        # Backup
        from boxmunge.commands.backup_cmd import run_backup
        assert run_backup(project_name, paths) == 0

        # Wipe database
        subprocess.run(
            ["docker", "compose", "-f", "compose.yml",
             "-p", compose_project,
             "exec", "-T", "db",
             "psql", "-U", "testuser", "-d", "testdb",
             "-c", "DROP TABLE IF EXISTS test_data; CREATE TABLE test_data (id SERIAL PRIMARY KEY, value TEXT);"],
            cwd=project_dir, check=True, capture_output=True, timeout=30,
        )

        # Verify wipe
        resp = urllib.request.urlopen(f"http://localhost:{port}/data")
        assert json.loads(resp.read())["count"] == 0

        # Restore
        from boxmunge.commands.restore import run_restore
        assert run_restore(project_name, paths, yes=True) == 0

        # Wait for web service to come back up after restore
        import time
        for _ in range(30):
            try:
                urllib.request.urlopen(f"http://localhost:{port}/healthz", timeout=2)
                break
            except Exception:
                time.sleep(1)

        # Verify recovery
        resp = urllib.request.urlopen(f"http://localhost:{port}/data")
        after_count = json.loads(resp.read())["count"]
        assert after_count == before_count

    def test_backup_missing_key_fails_cleanly(self, deployed_fixture) -> None:
        """Backup fails cleanly if the encryption key is missing."""
        paths, project_name, port, compose_project = deployed_fixture

        key = paths.backup_key
        key_backup = key.with_suffix(".bak")
        key.rename(key_backup)
        try:
            from boxmunge.commands.backup_cmd import run_backup
            result = run_backup(project_name, paths)
            assert result == 1
        finally:
            key_backup.rename(key)
