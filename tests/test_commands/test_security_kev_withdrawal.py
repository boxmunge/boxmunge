# SPDX-License-Identifier: Apache-2.0
"""A quarantine whose CVE this scan's KEV refresh withdrew is held, not
lifted: one source can drop an entry, so the operator accepts it with
`security resume` (#121 review). Docker and Trivy are stubbed."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from boxmunge.commands import quarantine_lift, security_scan_core
from boxmunge.commands.security_resume import security_resume_locked
from boxmunge.commands.security_scan_core import scan_one_project
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.quarantine import KEV_WITHDRAWAL_HOLD, is_quarantined, read_quarantine_state
from tests.test_commands.cve_helpers import (
    CRIT, Docker, Pushover, make_box, render_site, scan_result, seed_quarantine,
)

_CVE = CRIT.cve_id  # quarantined by seed_quarantine
MIRROR = "https://mirror.example/kev.json"
HELD = "Quarantine kept — CISA KEV withdrew"
LIFTED = "Quarantine lifted"


def _kev(withdrawn: frozenset[str] = frozenset()) -> KevCatalog:
    now = datetime.now(timezone.utc)
    return KevCatalog(frozenset(), now, now, MIRROR, withdrawn=withdrawn)


@pytest.fixture
def box(tmp_path, monkeypatch):
    paths = make_box(tmp_path, security={"posture": "balanced"})
    monkeypatch.setattr(security_scan_core, "scan_image",
                        lambda ref, timeout: scan_result(ref, [CRIT]))
    monkeypatch.setattr(quarantine_lift, "prepare_caddy_config", render_site)
    monkeypatch.setattr(quarantine_lift, "prepare_compose_override",
                        lambda p, m, component=None: None)
    paths.docker = Docker(monkeypatch)
    seed_quarantine(paths)
    return paths, Pushover(monkeypatch, paths)


def _titles(pushover, words: str) -> list[tuple[str, str, int]]:
    return [m for m in pushover.sent if words in m[0]]


def test_a_withdrawn_cve_holds_the_quarantine_and_alerts_once(box) -> None:
    paths, pushover = box
    scan_one_project(paths, "demo", in_grace=False, kev=_kev(frozenset({_CVE})))
    assert is_quarantined("demo", paths)
    assert "compose_up" not in paths.docker.calls
    assert read_quarantine_state("demo", paths)[KEV_WITHDRAWAL_HOLD] == MIRROR
    [(title, body, priority)] = _titles(pushover, HELD)
    assert priority == 1 and "[boxmunge:demo]" in title and _CVE in title
    assert MIRROR in body and "boxmunge security resume demo" in body
    assert not _titles(pushover, LIFTED)

    # Later scans see no withdrawal (the cache has moved on), but keep it held.
    pushover.clear()
    scan_one_project(paths, "demo", in_grace=False, kev=_kev())
    assert is_quarantined("demo", paths)
    assert not _titles(pushover, HELD) and not _titles(pushover, LIFTED)


def test_resume_accepts_the_withdrawal(box) -> None:
    paths, _ = box
    scan_one_project(paths, "demo", in_grace=False, kev=_kev(frozenset({_CVE})))
    now = datetime.now(timezone.utc).isoformat()
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(json.dumps({
        "source": MIRROR, "released_at": now, "fetched_at": now, "cve_ids": []}))
    assert security_resume_locked(paths, "demo") == 0
    assert not is_quarantined("demo", paths)
    assert "compose_up" in paths.docker.calls


def test_a_withdrawal_of_another_cve_does_not_hold(box) -> None:
    paths, pushover = box
    scan_one_project(paths, "demo", in_grace=False, kev=_kev(frozenset({"CVE-2000-0001"})))
    assert not is_quarantined("demo", paths)
    assert _titles(pushover, LIFTED) and not _titles(pushover, HELD)
