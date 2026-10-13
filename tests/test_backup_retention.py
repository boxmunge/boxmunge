"""Retention is tracked per backup kind (C-10).

One shared file count used to cover nightly, pre-deploy and container-update
backups, so the default "7 daily" held about 3.5 days, and ten deploys in a
day evicted every nightly backup.
"""

import re

import pytest

from boxmunge.backup import (
    BackupError, BackupKind, backup_filename, prune_backups, snapshot_kind,
)

DAY = "2026-03-{:02d}T020000"


def _make(bdir, project, day, kind=None):
    suffix = f"-{kind.value}" if kind else ""
    f = bdir / f"{project}-{DAY.format(day)}{suffix}.tar.gz.age"
    f.write_bytes(b"data")
    return f


class TestBackupFilename:
    def test_name_carries_timestamp_and_kind(self) -> None:
        name = backup_filename("myapp", BackupKind.PREDEPLOY)
        assert re.fullmatch(r"myapp-\d{4}-\d{2}-\d{2}T\d{6}-predeploy\.tar\.gz\.age", name)

    def test_every_kind_round_trips(self, tmp_path) -> None:
        for kind in BackupKind:
            path = tmp_path / backup_filename("my-app-2", kind)
            assert snapshot_kind(path, "my-app-2") is kind


class TestSnapshotKind:
    def test_archives_from_before_kinds_count_as_nightly(self, tmp_path) -> None:
        assert snapshot_kind(tmp_path / "myapp-2026-03-20T020000.tar.gz.age", "myapp") \
            is BackupKind.NIGHTLY

    @pytest.mark.parametrize("name", [
        "other-2026-03-20T020000-nightly.tar.gz.age",      # another project
        "myapp-extra-2026-03-20T020000.tar.gz.age",          # project prefix only
        "myapp-2026-03-20T020000-weekly.tar.gz.age",         # unknown kind
        ".encrypt-abc.tmp",
        "myapp-notes.txt",
    ])
    def test_unrecognised_names_have_no_kind(self, tmp_path, name) -> None:
        assert snapshot_kind(tmp_path / name, "myapp") is None


class TestPruneBackups:
    def test_ten_predeploy_snapshots_do_not_evict_nightlies(self, tmp_path) -> None:
        nightlies = [_make(tmp_path, "myapp", d, BackupKind.NIGHTLY) for d in range(1, 8)]
        predeploys = [_make(tmp_path, "myapp", d, BackupKind.PREDEPLOY) for d in range(10, 20)]

        assert prune_backups(tmp_path, "myapp", BackupKind.NIGHTLY, 7) == []
        pruned = prune_backups(tmp_path, "myapp", BackupKind.PREDEPLOY, 5)

        assert pruned == predeploys[:5]
        assert all(f.exists() for f in nightlies + predeploys[5:])

    def test_prunes_oldest_by_name_timestamp(self, tmp_path) -> None:
        files = [_make(tmp_path, "myapp", d, BackupKind.NIGHTLY) for d in (5, 1, 3)]
        assert prune_backups(tmp_path, "myapp", BackupKind.NIGHTLY, 2) == [files[1]]

    def test_legacy_archives_age_out_with_nightlies(self, tmp_path) -> None:
        legacy = _make(tmp_path, "myapp", 1)
        new = [_make(tmp_path, "myapp", d, BackupKind.NIGHTLY) for d in (2, 3)]
        assert prune_backups(tmp_path, "myapp", BackupKind.NIGHTLY, 2) == [legacy]
        assert all(f.exists() for f in new)

    def test_never_touches_unrecognised_files(self, tmp_path) -> None:
        keep = [
            _make(tmp_path, "other", 1, BackupKind.NIGHTLY),
            tmp_path / "myapp-2026-03-01T020000-weekly.tar.gz.age",
            tmp_path / ".encrypt-x.tmp",
        ]
        for f in keep[1:]:
            f.write_bytes(b"x")
        _make(tmp_path, "myapp", 2, BackupKind.NIGHTLY)
        prune_backups(tmp_path, "myapp", BackupKind.NIGHTLY, 1)
        assert all(f.exists() for f in keep)

    @pytest.mark.parametrize("retention", [0, -1])
    def test_retention_below_one_is_refused(self, tmp_path, retention) -> None:
        f = _make(tmp_path, "myapp", 1, BackupKind.NIGHTLY)
        with pytest.raises(BackupError, match="retention"):
            prune_backups(tmp_path, "myapp", BackupKind.NIGHTLY, retention)
        assert f.exists()
