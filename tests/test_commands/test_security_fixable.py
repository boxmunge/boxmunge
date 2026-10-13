# SPDX-License-Identifier: Apache-2.0
"""Fixable findings are never silent; fixable KEV findings quarantine (B-01)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from boxmunge.commands import security_scan_core, security_scan_inputs
from boxmunge.commands.security_scan_core import scan_one_project
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.policy import Disposition
from boxmunge.cve.quarantine import is_quarantined
from tests.test_commands.cve_helpers import Docker, Pushover, finding, make_box, scan_result

_XZ = "CVE-2024-3094"


def _kev(*ids: str) -> KevCatalog:
    return KevCatalog(frozenset(ids), datetime.now(timezone.utc))


@pytest.fixture
def box(tmp_path, monkeypatch):
    def build(posture: str, findings):
        paths = make_box(tmp_path, security={"posture": posture})
        monkeypatch.setattr(security_scan_inputs, "container_image_digest", lambda c: None)
        monkeypatch.setattr(
            security_scan_core, "scan_image", lambda ref, timeout: scan_result(ref, findings),
        )
        Docker(monkeypatch)
        return paths, Pushover(monkeypatch, paths)
    return build


@pytest.mark.parametrize("posture", ["balanced", "strict", "paranoid"])
def test_fixable_kev_quarantines_and_alerts(box, posture):
    """Audit B-01: a fixable, KEV-listed Critical produced 0 alerts and
    never quarantined, while nothing rebuilt the image."""
    paths, pushover = box(posture, [finding(_XZ, fix="5.6.1-2")])
    scan = scan_one_project(paths, "demo", in_grace=False, kev=_kev(_XZ))
    assert scan.decisions[0].findings[0].disposition is Disposition.QUARANTINE
    assert is_quarantined("demo", paths)
    [(title, body, priority)] = pushover.sent
    assert priority == 1 and "CISA KEV" in title
    assert "fix is available (5.6.1-2)" in body


def test_fixable_kev_under_relaxed_alerts_every_scan(box):
    paths, pushover = box("relaxed", [finding(_XZ, fix="5.6.1-2")])
    for _ in range(3):
        pushover.clear()
        scan_one_project(paths, "demo", in_grace=False, kev=_kev(_XZ))
        assert not is_quarantined("demo", paths)
        [(title, _, priority)] = pushover.sent
        assert priority == 1
        assert "fix available but not running" in title and _XZ in title


def test_fixable_over_threshold_alerts_once(box):
    paths, pushover = box("balanced", [finding("CVE-2026-0001", fix="3.0.15-1")])
    scan_one_project(paths, "demo", in_grace=False, kev=_kev())
    [(title, body, priority)] = pushover.sent
    assert priority == 0
    assert "1 fixable CVE finding over the quarantine gate" in title
    assert "CVE-2026-0001" in body
    assert not is_quarantined("demo", paths)
    pushover.clear()
    scan_one_project(paths, "demo", in_grace=False, kev=_kev())
    assert pushover.sent == []


def test_fixable_below_threshold_is_in_the_digest(box):
    """'Either way, you find out': a new below-gate fixable finding is
    listed in the informational digest, once."""
    from boxmunge.cve.scanner import Severity

    paths, pushover = box("balanced", [finding(sev=Severity.LOW, fix="1.1")])
    scan_one_project(paths, "demo", in_grace=False, kev=_kev())
    [(title, body, priority)] = pushover.sent
    assert priority == 0 and "1 new CVE finding" in title and "Fix available" in body
    pushover.clear()
    scan_one_project(paths, "demo", in_grace=False, kev=_kev())
    assert pushover.sent == []
