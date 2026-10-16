# SPDX-License-Identifier: Apache-2.0
"""Alert storms (audit B-13, B-14), through the real scan + scan-state path."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import yaml

from boxmunge.commands import security_actions, security_scan_core, security_scan_inputs
from boxmunge.commands.security_actions import cmd_security_scan
from boxmunge.commands.security_scan_core import scan_one_project
from boxmunge.cve.policy import ProjectDecision
from boxmunge.cve.scan_state import write_scan_state
from boxmunge.cve.scanner import Severity
from tests.test_commands.cve_helpers import (
    Docker,
    Pushover,
    finding,
    make_box,
    scan_result,
    seed_quarantine,
)


@pytest.fixture
def stubs(monkeypatch):
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    Docker(monkeypatch)
    digests = {"value": "sha256:" + "a" * 64}
    monkeypatch.setattr(
        security_scan_inputs, "container_image_digest", lambda c: digests["value"],
    )
    return digests


def _scan_returns(monkeypatch, findings) -> None:
    monkeypatch.setattr(
        security_scan_core, "scan_image",
        lambda ref, timeout: scan_result(ref, findings),
    )


def test_mixed_dispositions_alert_once_across_daily_scans(tmp_path, monkeypatch, stubs):
    """Audit B-13: libperl relevant (QUARANTINE), perl-base gated
    (INFORMATIONAL) for the same CVE. Day 1 alerts; days 2 and 3 do not."""
    paths = make_box(tmp_path, security={"runtimes": ["python"]})
    pushover = Pushover(monkeypatch, paths)
    _scan_returns(monkeypatch, [finding("CVE-2026-57433", pkg="libperl5.36"),
                                finding("CVE-2026-57433", pkg="perl-base")])
    scan_one_project(paths, "demo", in_grace=False)
    day1 = [p for _, _, p in pushover.sent]
    assert day1.count(1) == 1
    for _ in range(2):
        pushover.clear()
        scan_one_project(paths, "demo", in_grace=False)
        assert pushover.sent == []


def test_digest_change_does_not_re_alert(tmp_path, monkeypatch, stubs):
    """Audit B-14: 40 unchanged informational findings, new image digest."""
    paths = make_box(tmp_path)
    pushover = Pushover(monkeypatch, paths)
    _scan_returns(monkeypatch, [finding(f"CVE-2026-1{i:04d}", sev=Severity.LOW)
                                for i in range(40)])
    scan_one_project(paths, "demo", in_grace=False)
    assert len(pushover.sent) == 1  # one digest on the first scan
    pushover.clear()
    stubs["value"] = "sha256:" + "b" * 64
    scan_one_project(paths, "demo", in_grace=False)
    assert pushover.sent == []


def test_host_suppression_expiry_alerts_once_per_fleet_run(tmp_path, monkeypatch, stubs):
    paths = make_box(tmp_path, projects=("aaa", "bbb", "ccc"))
    pushover = Pushover(monkeypatch, paths)
    _scan_returns(monkeypatch, [])
    today = datetime.now(timezone.utc).date()
    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    # Every project's prior scan was yesterday, while the suppression applied.
    for name in ("aaa", "bbb", "ccc"):
        paths.project_scan_state(name).parent.mkdir(parents=True, exist_ok=True)
        write_scan_state(paths.project_scan_state(name), scanned_at=yesterday, decisions=(
            ProjectDecision(name, f"{name}-web:1", (), False, False, yesterday),
        ))
    paths.host_suppressions.write_text(yaml.safe_dump({"suppressions": [{
        "cve": "CVE-2026-0007", "until": today.isoformat(), "reason": "r",
        "reviewed_by": "ops", "added": (today - timedelta(days=30)).isoformat(),
    }]}))
    assert cmd_security_scan([], paths) == 0
    host = [t for t in pushover.titles() if "Host suppression expired" in t]
    assert len(host) == 1 and host[0].endswith("] Host suppression expired — CVE-2026-0007")
    assert not [t for t in pushover.titles() if "Suppression expired" in t]


def test_quarantined_project_rescan_is_silent(tmp_path, monkeypatch, stubs):
    """A project that stays quarantined is not re-alerted every day."""
    paths = make_box(tmp_path)
    pushover = Pushover(monkeypatch, paths)
    _scan_returns(monkeypatch, [finding()])
    scan_one_project(paths, "demo", in_grace=False)
    assert [p for _, _, p in pushover.sent] == [1]
    pushover.clear()
    seed_quarantine(paths)
    scan_one_project(paths, "demo", in_grace=False)
    assert pushover.sent == []

