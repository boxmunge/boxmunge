"""run_backup tags each snapshot with its kind and prunes only that kind (C-10)."""

from unittest.mock import patch

import pytest

from boxmunge.backup import BackupKind, snapshot_kind
from boxmunge.commands import backup_cmd
from boxmunge.commands.backup_cmd import run_backup, run_backup_all
from boxmunge.paths import BoxPaths

MANIFEST = """\
project: myapp
services:
  web:
    port: 3000
backup:
  type: postgres
  service: db
  dump_command: "pg_dump x"
  restore_command: "psql x"
{retention}
"""


def _project(paths: BoxPaths, retention: str = "  retention: 7") -> None:
    pdir = paths.project_dir("myapp")
    (pdir / "backups").mkdir(parents=True)
    (pdir / "manifest.yml").write_text(MANIFEST.format(retention=retention))


def _seed(paths: BoxPaths, kind: BackupKind, days: range) -> list:
    out = []
    for d in days:
        f = paths.project_backups("myapp") / f"myapp-2026-01-{d:02d}T020000-{kind.value}.tar.gz.age"
        f.write_bytes(b"old")
        out.append(f)
    return out


def _fake_dump(paths, project_name, dump_command, service):
    raw = paths.project_backups(project_name) / ".dump-x.tar.gz"
    raw.write_bytes(b"dump")
    return raw


@pytest.fixture
def no_dump():
    with patch.object(backup_cmd, "execute_dump", side_effect=_fake_dump):
        yield


def _kinds(paths: BoxPaths) -> dict[BackupKind, int]:
    counts: dict[BackupKind, int] = {}
    for f in paths.project_backups("myapp").iterdir():
        kind = snapshot_kind(f, "myapp")
        if kind:
            counts[kind] = counts.get(kind, 0) + 1
    return counts


class TestKindedBackup:
    def test_predeploy_snapshot_prunes_only_predeploys(
        self, paths, system_container, no_dump,
    ) -> None:
        _project(paths)
        nightlies = _seed(paths, BackupKind.NIGHTLY, range(1, 8))
        predeploys = _seed(paths, BackupKind.PREDEPLOY, range(10, 15))

        assert run_backup("myapp", paths, kind=BackupKind.PREDEPLOY) == 0

        assert all(f.exists() for f in nightlies)
        assert not predeploys[0].exists()
        assert _kinds(paths) == {BackupKind.NIGHTLY: 7, BackupKind.PREDEPLOY: 5}

    def test_nightly_uses_manifest_retention(self, paths, system_container, no_dump) -> None:
        _project(paths, retention="  retention: 3")
        _seed(paths, BackupKind.NIGHTLY, range(1, 4))
        _seed(paths, BackupKind.MANUAL, range(5, 7))
        assert run_backup("myapp", paths, kind=BackupKind.NIGHTLY) == 0
        assert _kinds(paths) == {BackupKind.NIGHTLY: 3, BackupKind.MANUAL: 2}

    def test_default_kind_is_manual(self, paths, system_container, no_dump) -> None:
        _project(paths)
        assert run_backup("myapp", paths) == 0
        assert _kinds(paths) == {BackupKind.MANUAL: 1}

    @pytest.mark.parametrize("retention", ["  retention: 0", "  retention: '7'", "  retention: true"])
    def test_invalid_nightly_retention_fails_before_dumping(
        self, paths, system_container, retention, capsys,
    ) -> None:
        _project(paths, retention=retention)
        with patch.object(backup_cmd, "execute_dump") as dump:
            assert run_backup("myapp", paths, kind=BackupKind.NIGHTLY) == 1
        dump.assert_not_called()
        assert "backup.retention" in capsys.readouterr().err


class TestBackupAllIsNightly:
    def test_backup_all_takes_nightly_snapshots(self, paths) -> None:
        _project(paths)
        with patch.object(backup_cmd, "run_backup", return_value=0) as rb:
            assert run_backup_all(paths) == 0
        assert rb.call_args.kwargs["kind"] is BackupKind.NIGHTLY
