# SPDX-License-Identifier: Apache-2.0
"""Monthly rotation of the audit log by root: the attribute is cleared only
for the moves, every archive and the new active file end up append-only, and
12 archives are kept."""
from __future__ import annotations

import errno
import os
import stat
import sys
from datetime import date

import pytest

from boxmunge.api import audit_rotate, audit_seal
from boxmunge.api.audit_rotate import AUDIT_ARCHIVES_KEPT, rotate
from boxmunge.api.audit_seal import SealError, seal
from boxmunge.paths import BoxPaths
from tests.api.fake_attr import install

DAY = date(2026, 12, 1)


@pytest.fixture
def attr(monkeypatch):
    return install(monkeypatch)


@pytest.fixture
def sealed(paths, attr):
    seal(paths)
    with open(paths.audit_log, "a") as f:
        f.write('{"outcome":"accepted"}\n')
    return paths


def test_rotate_archives_with_append_kept_and_new_file_sealed(sealed, attr) -> None:
    old_ino = os.lstat(sealed.audit_log).st_ino
    assert rotate(sealed, DAY) == "audit.jsonl.2026-12-01"
    archive = sealed.logs / "audit.jsonl.2026-12-01"
    assert os.lstat(archive).st_ino == old_ino
    assert archive.read_text() == '{"outcome":"accepted"}\n'
    assert attr.append_only(archive)
    st = os.lstat(sealed.audit_log)
    assert st.st_ino != old_ino and st.st_size == 0
    assert stat.S_IMODE(st.st_mode) == 0o640 and st.st_uid == os.getuid()
    assert attr.append_only(sealed.audit_log)


def test_rotate_adopts_a_file_a_writer_created_mid_rotation(sealed, attr, monkeypatch) -> None:
    """A writer that finds the name gone and creates it (dev mode does) keeps
    its lines: rotation opens without O_EXCL and seals the file it finds."""
    real_rename = os.rename

    def rename_then_writer_creates(src, dst, *a, **k):
        real_rename(src, dst, *a, **k)
        if str(src) != str(sealed.audit_log):
            return
        with open(sealed.audit_log, "w") as f:
            f.write('{"outcome":"refused"}\n')
        os.chmod(sealed.audit_log, 0o666)

    monkeypatch.setattr(audit_rotate.os, "rename", rename_then_writer_creates)
    rotate(sealed, DAY)
    assert sealed.audit_log.read_text() == '{"outcome":"refused"}\n'
    assert stat.S_IMODE(os.lstat(sealed.audit_log).st_mode) == 0o640
    assert attr.append_only(sealed.audit_log)


def test_rotate_keeps_12_archives(sealed, attr, monkeypatch) -> None:
    olds = []
    for month in range(1, 13):
        archive = sealed.logs / f"audit.jsonl.2025-{month:02d}-01"
        archive.write_text("old\n")
        attr.flags[os.lstat(archive).st_ino] = audit_seal.FS_APPEND_FL
        olds.append(archive)
    unrelated = sealed.logs / "audit.jsonl.notes"
    unrelated.write_text("kept\n")
    cleared: list[int] = []
    real_unlink = os.unlink

    def unlink(path, *a, **k):
        if os.path.dirname(path) == str(sealed.logs):
            assert not attr.append_only(path), f"{path} unlinked while append-only"
            cleared.append(1)
        real_unlink(path, *a, **k)

    monkeypatch.setattr(audit_rotate.os, "unlink", unlink)
    rotate(sealed, DAY)
    archives = sorted(p.name for p in sealed.logs.glob("audit.jsonl.2*"))
    assert len(archives) == AUDIT_ARCHIVES_KEPT == 12
    assert archives[0] == "audit.jsonl.2025-02-01" and archives[-1] == "audit.jsonl.2026-12-01"
    assert not olds[0].exists() and cleared == [1]
    assert unrelated.exists()


def test_rotate_of_an_empty_log_does_nothing(paths, attr) -> None:
    seal(paths)
    ino = os.lstat(paths.audit_log).st_ino
    assert rotate(paths, DAY) is None
    assert os.lstat(paths.audit_log).st_ino == ino and attr.append_only(paths.audit_log)
    assert list(paths.logs.glob("audit.jsonl.*")) == []


def test_rotate_refuses_an_archive_name_already_taken_before_touching_anything(sealed, attr) -> None:
    taken = sealed.logs / "audit.jsonl.2026-12-01"
    taken.write_text("")
    with pytest.raises(SealError, match="already exists") as excinfo:
        rotate(sealed, DAY)
    assert attr.append_only(sealed.audit_log)
    assert f"sudo mv {taken} {taken}.old" in excinfo.value.fix
    assert "_audit-seal" not in excinfo.value.fix
    assert not os.path.lexists(sealed.audit_rotating)


def test_a_linked_archive_past_the_kept_names_its_removal(sealed, attr, tmp_path) -> None:
    for month in range(1, 13):
        (sealed.logs / f"audit.jsonl.2025-{month:02d}-01").write_text("old\n")
    (sealed.logs / "audit.jsonl.2024-01-01").symlink_to(tmp_path / "gone")
    with pytest.raises(SealError, match="step 5") as excinfo:
        rotate(sealed, DAY)
    assert f"sudo rm {sealed.logs / 'audit.jsonl.2024-01-01'}" in excinfo.value.fix
    assert not os.path.lexists(sealed.audit_rotating)


def test_health_warns_while_a_rotation_has_the_log_moved_aside(sealed, attr, monkeypatch) -> None:
    """A health tick between the move and the new log must not error: in
    probation an error rolls the upgrade back."""
    from boxmunge.health_checks.audit_log import check_audit_log
    seen = []
    real_rename = os.rename

    def rename_then_health(src, dst, *a, **k):
        real_rename(src, dst, *a, **k)
        if str(src) == str(sealed.audit_log):
            seen.append(check_audit_log(sealed))

    monkeypatch.setattr(audit_rotate.os, "rename", rename_then_health)
    rotate(sealed, DAY)
    (during,) = seen
    assert (during.status, during.detail.split(":")[0]) == ("warn", "rotation in progress")
    assert not os.path.lexists(sealed.audit_rotating)
    assert check_audit_log(sealed).status == "ok"


def test_a_stale_rotation_marker_is_ignored(paths, attr) -> None:
    from boxmunge.health_checks.audit_log import check_audit_log
    audit_seal.mark_rotating(paths)
    old = audit_seal.time.time() - audit_seal.ROTATION_MARKER_FRESH_SECONDS - 1
    os.utime(paths.audit_rotating, (old, old))
    assert check_audit_log(paths).status == "error"   # the log is missing


def test_rotate_of_a_missing_log_names_the_seal(paths, attr) -> None:
    with pytest.raises(SealError, match="missing") as excinfo:
        rotate(paths, DAY)
    assert excinfo.value.fix == audit_seal.SEAL_FIX


def test_rotate_on_unsupported_host_rotates_without_attribute_steps(paths, attr,
                                                                  monkeypatch) -> None:
    attr.fail = errno.EOPNOTSUPP
    seal(paths)
    paths.audit_log.write_text("line\n")
    calls: list[int] = []
    real = attr.__call__
    attr.fail = None
    monkeypatch.setattr(audit_seal, "_ioctl", lambda *a: calls.append(1) or real(*a))
    assert rotate(paths, DAY) == "audit.jsonl.2026-12-01"
    assert calls == []
    assert (paths.logs / "audit.jsonl.2026-12-01").read_text() == "line\n"
    st = os.lstat(paths.audit_log)
    assert st.st_size == 0 and stat.S_IMODE(st.st_mode) == 0o640


def test_failed_rotation_alerts_the_fix(sealed, attr, monkeypatch, capsys) -> None:
    from boxmunge.commands import audit_cmd
    monkeypatch.setattr(BoxPaths.__init__, "__defaults__", (sealed.root,))
    monkeypatch.setattr(audit_cmd, "running_as_root", lambda: True)
    sent: list[tuple[str, str, int]] = []
    monkeypatch.setattr(audit_cmd, "notify",
                        lambda paths, title, body, *, component, priority=0:
                        sent.append((title, body, priority)) or True)
    attr.fail_set = errno.EIO
    monkeypatch.setattr(sys, "argv", ["boxmunge-server", "_audit-rotate"])
    with pytest.raises(SystemExit) as excinfo:
        audit_cmd.cmd_audit_rotate([])
    assert excinfo.value.code == 1
    (title, body, priority), = sent
    assert priority == 1
    assert "step 1" in body and "sudo boxmunge-server _audit-seal" in body
    assert "sudo boxmunge-server _audit-seal" in capsys.readouterr().err
    logged = sealed.log_file.read_text()
    assert "audit" in logged and "_audit-seal" in logged
