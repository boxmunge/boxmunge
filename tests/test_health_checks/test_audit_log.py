# SPDX-License-Identifier: Apache-2.0
"""The audit-log health check. An error means a platform control is off (the
log is gone, or lost its append-only attribute on a host that supports it),
so probation rolling an upgrade back over it is right. A host recorded as
unable to set the attribute only warns, so it can still upgrade."""
from __future__ import annotations

import errno
import os

import pytest

from boxmunge.api.audit_seal import seal
from boxmunge.health_checks.audit_log import check_audit_log
from tests.api.fake_attr import install


@pytest.fixture
def attr(monkeypatch):
    return install(monkeypatch)


def test_ok_when_sealed(paths, attr) -> None:
    seal(paths)
    check = check_audit_log(paths)
    assert (check.name, check.status, check.detail) == ("audit-log", "ok", "append-only")


def test_health_error_when_append_missing(paths, attr) -> None:
    seal(paths)
    attr.clear(paths.audit_log)
    check = check_audit_log(paths)
    assert check.status == "error"
    assert "set it again as root: boxmunge-server _audit-seal" in check.detail


def test_health_errors_when_attribute_cleared_on_a_supporting_host(paths, attr) -> None:
    """No record: the host set the attribute at install, so its absence is
    a control switched off, not a limit of the host."""
    seal(paths)
    attr.clear(paths.audit_log)
    assert not paths.audit_append_unsupported.exists()
    assert check_audit_log(paths).status == "error"


def test_health_warns_not_errors_on_a_recorded_unsupported_host(paths, attr) -> None:
    attr.fail = errno.EOPNOTSUPP
    seal(paths)
    check = check_audit_log(paths)
    assert check.status == "warn"
    assert f"{errno.errorcode[errno.EOPNOTSUPP]} {paths.logs}" in check.detail
    assert "deploy can rewrite the audit log on this host" in check.detail


def test_a_planted_record_does_not_downgrade_the_error(paths, attr, monkeypatch) -> None:
    from boxmunge.api import audit_seal
    seal(paths)
    attr.clear(paths.audit_log)
    paths.upgrade_root.mkdir(mode=0o700)
    paths.audit_append_unsupported.write_text("EOPNOTSUPP /opt/boxmunge/logs\n")
    monkeypatch.setattr(audit_seal, "_root_owner", lambda: (0, 0))
    check = check_audit_log(paths)
    assert check.status == "error" and "not root's" in check.detail


@pytest.mark.parametrize("kind", ["missing", "symlink", "hardlink", "directory"])
def test_health_error_when_log_missing_or_linked(paths, attr, tmp_path, kind) -> None:
    if kind == "symlink":
        (tmp_path / "real").write_text("")
        paths.audit_log.symlink_to(tmp_path / "real")
    elif kind == "hardlink":
        (paths.logs / "other").write_text("")
        os.link(paths.logs / "other", paths.audit_log)
    elif kind == "directory":
        paths.audit_log.mkdir()
    check = check_audit_log(paths)
    assert check.status == "error"
    assert "recreate as root: boxmunge-server _audit-seal" in check.detail
