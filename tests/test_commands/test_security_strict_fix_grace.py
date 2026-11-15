# SPDX-License-Identifier: Apache-2.0
"""Strict's fix grace through the real scan: an available fix not deployed in
7 days is warned of 48 hours before, then quarantines; deploying the fix
lifts it. Only Docker and Trivy are stubbed."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from boxmunge.commands import quarantine_lift, security_scan_core
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.policy import Disposition
from boxmunge.cve.quarantine import is_quarantined
from tests.test_commands.cve_helpers import (
    Docker, Pushover, finding, make_box, render_site, scan_and_send, scan_result,
)

T0 = datetime(2026, 11, 1, 3, 0, tzinfo=timezone.utc)
FIXABLE = finding(fix="2")


@pytest.fixture
def box(tmp_path, monkeypatch):
    paths = make_box(tmp_path, security={"posture": "strict"})
    paths.found = [FIXABLE]
    monkeypatch.setattr(security_scan_core, "scan_image",
                        lambda ref, timeout: scan_result(ref, paths.found))
    monkeypatch.setattr(quarantine_lift, "prepare_caddy_config", render_site)
    monkeypatch.setattr(quarantine_lift, "prepare_compose_override",
                        lambda p, m, component=None: None)
    paths.docker = Docker(monkeypatch)
    return paths, Pushover(monkeypatch, paths), monkeypatch


def _scan(box, at: datetime):
    paths, _, monkeypatch = box
    monkeypatch.setattr(security_scan_core, "_now", lambda: at)
    now = datetime.now(timezone.utc)
    return scan_and_send(paths, "demo", kev=KevCatalog(frozenset(), now, now, "test"))


def _titles(pushover, words: str) -> list[str]:
    return [t for t in pushover.titles() if words in t]


def test_undeployed_fix_is_warned_then_quarantined_then_lifted(box) -> None:
    paths, pushover, _ = box
    fd = _scan(box, T0).decisions[0].findings[0]
    assert fd.disposition is Disposition.IGNORED_FIXED and fd.fix_would_quarantine
    assert not is_quarantined("demo", paths)

    _scan(box, T0 + timedelta(days=5, hours=1))
    [warning] = [s for s in pushover.sent if "Fix deadline 2026-11-08" in s[0]]
    assert warning[2] == 0 and "before 2026-11-08" in warning[1]
    _scan(box, T0 + timedelta(days=5, hours=6))
    assert len(_titles(pushover, "Fix deadline")) == 1

    scan = _scan(box, T0 + timedelta(days=7))
    assert scan.decisions[0].findings[0].disposition is Disposition.QUARANTINE
    assert is_quarantined("demo", paths)
    [title] = _titles(pushover, "QUARANTINED")
    assert "fix not deployed" in title
    stored = json.loads(paths.project_scan_state("demo").read_text())
    assert "quarantine" in json.dumps(stored)

    paths.found = []                                     # the fix is deployed
    _scan(box, T0 + timedelta(days=7, hours=2))
    assert not is_quarantined("demo", paths)
    assert _titles(pushover, "Quarantine lifted")
    assert json.loads(paths.project_fix_grace("demo").read_text()) == {"entries": []}


def test_audit_only_scan_applies_the_deadline_but_records_nothing(box) -> None:
    paths, pushover, monkeypatch = box
    _scan(box, T0)
    record = paths.project_fix_grace("demo").read_text()
    monkeypatch.setattr(security_scan_core, "_now", lambda: T0 + timedelta(days=8))
    now = datetime.now(timezone.utc)
    scan = security_scan_core.scan_one_project(
        paths, "demo", audit_only=True, kev=KevCatalog(frozenset(), now, now, "test"))
    assert scan.decisions[0].findings[0].disposition is Disposition.QUARANTINE
    assert paths.project_fix_grace("demo").read_text() == record
    assert not _titles(pushover, "Fix deadline")
