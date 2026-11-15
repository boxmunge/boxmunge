# SPDX-License-Identifier: Apache-2.0
"""Sealing the audit log: install makes logs/audit.jsonl deploy's, 0640 and
append-only. A host that cannot set the attribute is recorded and installs
anyway; any other failure to set it fails the seal."""
from __future__ import annotations

import errno
import os
import stat

import pytest

from boxmunge.api import audit_seal
from boxmunge.api.audit import AuditLog
from boxmunge.api.audit_seal import AppendUnsupported, SealError, seal
from boxmunge.api.invoke import Invoker
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.registry import Action, Registry
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.api.schema import BOOLEAN, obj
from tests.api.fake_attr import install
from tests.api.fakes import StubHost


@pytest.fixture
def attr(monkeypatch):
    return install(monkeypatch)


def test_seal_creates_deploy_owned_0640_and_sets_append(paths, attr) -> None:
    seal(paths)
    st = os.lstat(paths.audit_log)
    assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o640
    assert (st.st_uid, st.st_gid) == (os.getuid(), os.getgid())
    assert attr.append_only(paths.audit_log)
    assert not os.path.lexists(paths.audit_append_unsupported)


def test_seal_keeps_what_the_log_holds_and_seals_it_again(paths, attr) -> None:
    paths.audit_log.write_text('{"outcome":"accepted"}\n')
    paths.audit_log.chmod(0o666)
    seal(paths)
    seal(paths)   # sealed already: cleared for the chmod, then set again
    assert paths.audit_log.read_text() == '{"outcome":"accepted"}\n'
    assert stat.S_IMODE(os.lstat(paths.audit_log).st_mode) == 0o640
    assert attr.append_only(paths.audit_log)


def test_seal_refuses_a_symlink(paths, attr, tmp_path) -> None:
    target = tmp_path / "elsewhere"
    target.write_text("")
    target.chmod(0o600)
    paths.audit_log.symlink_to(target)
    with pytest.raises(SealError, match="symlink"):
        seal(paths)
    assert not attr.flags
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert os.path.islink(paths.audit_log)


def test_seal_refuses_a_fifo_without_blocking(paths, attr) -> None:
    os.mkfifo(paths.audit_log)
    with pytest.raises(SealError, match="FIFO|regular"):
        seal(paths)


@pytest.mark.parametrize("code", [errno.EOPNOTSUPP, errno.ENOTTY, errno.EPERM])
def test_unsupported_host_is_recorded_and_install_goes_on(paths, attr, code) -> None:
    attr.fail = code
    seal(paths)   # returns: install goes on
    record = paths.audit_append_unsupported.read_text()
    assert record == f"{errno.errorcode[code]} {paths.logs}\n"
    st = os.lstat(paths.audit_log)
    assert stat.S_IMODE(st.st_mode) == 0o640 and st.st_uid == os.getuid()
    assert audit_seal.read_unsupported(paths) == record.strip()


def test_a_later_seal_that_succeeds_removes_the_record(paths, attr) -> None:
    attr.fail = errno.EOPNOTSUPP
    seal(paths)
    attr.fail = None
    seal(paths)
    assert not os.path.lexists(paths.audit_append_unsupported)
    assert attr.append_only(paths.audit_log)


def test_other_attribute_errors_still_fail_the_seal(paths, attr) -> None:
    attr.fail_set = errno.EIO
    with pytest.raises(SealError, match="EIO") as excinfo:
        seal(paths)
    assert not isinstance(excinfo.value, AppendUnsupported)
    assert not os.path.lexists(paths.audit_append_unsupported)


def test_eperm_is_not_unsupported_when_not_root(paths, attr, monkeypatch) -> None:
    monkeypatch.setattr(audit_seal, "running_as_root", lambda: False)
    attr.fail_set = errno.EPERM
    with pytest.raises(SealError) as excinfo:
        seal(paths)
    assert not isinstance(excinfo.value, AppendUnsupported)


def test_the_unsupported_message_names_the_filesystem(paths, attr) -> None:
    attr.fail = errno.EOPNOTSUPP
    fd = os.open(paths.logs, os.O_RDONLY)
    try:
        with pytest.raises(AppendUnsupported) as excinfo:
            audit_seal.set_append_only(fd, True, where=paths.audit_log)
    finally:
        os.close(fd)
    assert (f"the filesystem under {paths.logs} does not support the append-only attribute"
            in str(excinfo.value))


def test_the_record_is_root_only(paths, attr) -> None:
    """In upgrade-root/, root's alone: deploy cannot rename a file into it."""
    attr.fail = errno.EOPNOTSUPP
    seal(paths)
    assert paths.audit_append_unsupported.parent == paths.upgrade_root
    assert stat.S_IMODE(os.lstat(paths.upgrade_root).st_mode) == 0o700
    assert stat.S_IMODE(os.lstat(paths.audit_append_unsupported).st_mode) == 0o600


def test_a_record_root_did_not_write_is_refused(paths, attr, monkeypatch) -> None:
    """A record that is not root's own must not unseal the log."""
    paths.upgrade_root.mkdir(mode=0o700)
    paths.audit_append_unsupported.write_text("EOPNOTSUPP /opt/boxmunge/logs\n")
    monkeypatch.setattr(audit_seal, "_root_owner", lambda: (0, 0))
    with pytest.raises(SealError, match="not root's"):
        audit_seal.read_unsupported(paths)


def test_a_linked_record_is_refused(paths, attr, tmp_path) -> None:
    (tmp_path / "real").write_text("EOPNOTSUPP /x\n")
    paths.upgrade_root.mkdir(mode=0o700)
    paths.audit_append_unsupported.symlink_to(tmp_path / "real")
    with pytest.raises(SealError, match="symlink"):
        audit_seal.read_unsupported(paths)


def test_seal_sets_the_attribute_again_on_archives(paths, attr) -> None:
    """A rotation that failed at step 3 left an archive without it."""
    archive = paths.logs / "audit.jsonl.2026-11-01"
    archive.write_text("old\n")
    seal(paths)
    assert attr.append_only(archive) and attr.append_only(paths.audit_log)


def test_seal_refuses_a_linked_archive_naming_its_removal(paths, attr, tmp_path) -> None:
    (tmp_path / "real").write_text("")
    (paths.logs / "audit.jsonl.2026-11-01").symlink_to(tmp_path / "real")
    with pytest.raises(SealError) as excinfo:
        seal(paths)
    assert f"sudo rm {paths.logs / 'audit.jsonl.2026-11-01'}" in excinfo.value.fix
    assert not attr.flags.get(os.lstat(tmp_path / "real").st_ino)


def test_unwritable_audit_log_refuses_the_call_and_runs_nothing(paths, attr) -> None:
    """The sealed log, with +a faked off and the file made read-only: the
    production writer cannot append, so nothing runs."""
    seal(paths)
    attr.clear(paths.audit_log)
    paths.audit_log.chmod(0o440)
    ran: list[dict] = []
    registry = Registry()
    registry.register(Action(
        name="secret.set", tier=Tier.GOVERN, summary="Test action.",
        params=obj({}), result=obj({"ok": BOOLEAN}),
        handler=lambda params, ctx: ran.append(params) or {"ok": True}))
    invoker = Invoker(registry, paths, StubHost(), AuditLog(paths.audit_log, create=False))
    with pytest.raises(ActionError) as excinfo:
        invoker.invoke("secret.set", {}, Principal.operator())
    assert excinfo.value.code is ErrorCode.UNAVAILABLE
    assert "did not run" in excinfo.value.message
    assert ran == []
    assert paths.audit_log.read_text() == ""
