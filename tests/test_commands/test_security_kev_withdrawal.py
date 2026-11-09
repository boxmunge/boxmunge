# SPDX-License-Identifier: Apache-2.0
"""A quarantine whose CVE a KEV refresh withdrew is held, not lifted: one
source can drop an entry, so the operator accepts it with `security resume`.
The refresh records the withdrawal, so the hold applies in every later run,
not only the one that withdrew it (#121 reviews). Docker and Trivy are
stubbed."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from boxmunge.commands import quarantine_gate as gate
from boxmunge.commands import quarantine_lift, security_scan_core
from boxmunge.commands.security_resume import security_resume_locked
from boxmunge.commands.security_scan_core import scan_one_project
from boxmunge.cve import kev_refresh
from boxmunge.cve.kev import KevCatalog
# Imported before conftest's autouse stub replaces the module attribute.
from boxmunge.cve.kev_refresh import refresh_from, refresh_kev
from boxmunge.cve.kev_withdrawals import load_withdrawals
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.cve.scanner import ScannerError
from boxmunge.release_target import production_target
from tests.test_commands.cve_helpers import (
    CRIT, Docker, Pushover, finding, make_box, render_site, scan_result, seed_quarantine,
)
from tests.test_commands.test_quarantine_gate import MANIFEST, Box

_CVE = CRIT.cve_id  # quarantined by seed_quarantine
MIRROR = "https://mirror.example/kev.json"
HELD = "Quarantine kept — CISA KEV withdrew"
LIFTED = "Quarantine lifted"


class _Resp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, limit: int = -1) -> bytes:
        return self._body


def _ids(n: int) -> list[str]:
    return [f"CVE-2020-{i:05d}" for i in range(n)]


def _catalog(paths, ids: list[str]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(json.dumps({
        "source": MIRROR, "released_at": now, "fetched_at": now, "cve_ids": ids}))


def _refresh(paths, monkeypatch, ids: list[str]) -> None:
    """One refresh run: MIRROR serves a catalog of ``ids``."""
    body = json.dumps({"dateReleased": datetime.now(timezone.utc).isoformat(),
                       "vulnerabilities": [{"cveID": c} for c in ids]}).encode()
    monkeypatch.setattr(kev_refresh, "_open", lambda req: _Resp(body))
    assert refresh_from(paths, (MIRROR,)).updated


def _kev() -> KevCatalog:
    """The cache after the withdrawing refresh: _CVE no longer listed."""
    now = datetime.now(timezone.utc)
    return KevCatalog(frozenset(_ids(1400)), now, now, MIRROR)


@pytest.fixture
def box(tmp_path, monkeypatch):
    paths = make_box(tmp_path, security={"posture": "balanced"})
    paths.flaky = False

    def scan(ref, timeout):
        if paths.flaky:
            raise ScannerError("registry unreachable")
        return scan_result(ref, paths.found)

    paths.found = [CRIT]
    monkeypatch.setattr(security_scan_core, "scan_image", scan)
    monkeypatch.setattr(quarantine_lift, "prepare_caddy_config", render_site)
    monkeypatch.setattr(quarantine_lift, "prepare_compose_override",
                        lambda p, m, component=None: None)
    paths.docker = Docker(monkeypatch)
    seed_quarantine(paths)
    _catalog(paths, _ids(1400) + [_CVE])
    _refresh(paths, monkeypatch, _ids(1400))  # the run that withdraws _CVE
    return paths, Pushover(monkeypatch, paths)


def _sent(pushover, words: str) -> list[tuple[str, str, int]]:
    return [m for m in pushover.sent if words in m[0]]


def test_the_refresh_records_the_withdrawal(box) -> None:
    paths, _ = box
    assert load_withdrawals(paths)[_CVE].source == MIRROR


def test_a_clean_scan_holds_the_quarantine_and_alerts_once(box) -> None:
    paths, pushover = box
    for _ in range(3):
        scan_one_project(paths, "demo", in_grace=False, kev=_kev())
        assert is_quarantined("demo", paths)
        assert "compose_up" not in paths.docker.calls
    [(title, body, priority)] = _sent(pushover, HELD)
    assert priority == 1 and "[boxmunge:demo]" in title and _CVE in title
    assert MIRROR in body and "boxmunge security resume demo" in body
    assert not _sent(pushover, LIFTED)


def test_an_incomplete_scan_in_the_withdrawing_run_keeps_the_hold(box) -> None:
    """The withdrawing run's scan of the project failed; the next run's
    refresh withdraws nothing, and its clean scan must still hold."""
    paths, pushover = box
    paths.flaky = True
    with pytest.raises(RuntimeError):
        scan_one_project(paths, "demo", in_grace=False, kev=_kev())
    paths.flaky = False
    scan_one_project(paths, "demo", in_grace=False, kev=_kev())
    assert is_quarantined("demo", paths)
    assert _sent(pushover, HELD) and not _sent(pushover, LIFTED)


def test_a_project_absent_from_the_withdrawing_run_is_held(box, monkeypatch) -> None:
    """`security scan <other>` refreshed KEV; 'demo' is first scanned a run
    later, after another refresh that withdrew nothing."""
    paths, pushover = box
    _refresh(paths, monkeypatch, _ids(1400))
    scan_one_project(paths, "demo", in_grace=False, kev=_kev())
    assert is_quarantined("demo", paths) and _sent(pushover, HELD)


def test_resume_accepts_the_withdrawal(box) -> None:
    paths, _ = box
    scan_one_project(paths, "demo", in_grace=False, kev=_kev())
    assert security_resume_locked(paths, "demo") == 0
    assert not is_quarantined("demo", paths)
    assert "compose_up" in paths.docker.calls


def test_images_without_the_cve_are_a_fix_and_lift(box) -> None:
    paths, pushover = box
    paths.found = []
    scan_one_project(paths, "demo", in_grace=False, kev=_kev())
    assert not is_quarantined("demo", paths)
    assert _sent(pushover, LIFTED) and not _sent(pushover, HELD)


def test_the_cve_listed_again_ends_the_withdrawal(box, monkeypatch) -> None:
    paths, _ = box
    _refresh(paths, monkeypatch, _ids(1400) + [_CVE])
    assert _CVE not in load_withdrawals(paths)


def test_an_unreadable_withdrawals_file_keeps_the_quarantine(box) -> None:
    paths, _ = box
    paths.kev_withdrawn.write_text("{")
    scan_one_project(paths, "demo", in_grace=False, kev=_kev())
    assert is_quarantined("demo", paths)


def test_the_deploy_gate_holds_a_release_that_still_has_the_cve(tmp_path, monkeypatch) -> None:
    gate_box = Box(tmp_path, monkeypatch)
    paths = gate_box.paths
    _catalog(paths, _ids(1400) + ["CVE-2026-0001"])
    _refresh(paths, monkeypatch, _ids(1400))  # withdraws the quarantine's CVE
    gate_box.findings["postgres@sha256:" + "b" * 64] = (CRIT,)
    with pytest.raises(gate.QuarantineRefused) as e:
        gate_box.clear(MANIFEST)
    text = str(e.value)
    assert "still contains CVE-2026-0001 (catalog from " + MIRROR in text
    assert "boxmunge security resume demo" in text
    gate_box.findings.clear()  # a release without the CVE is a fix
    assert gate.clear_release(paths, production_target(paths, "demo"), MANIFEST)


# ---- through the fleet scan: the withdrawing run never reaches 'demo' ----


def _fleet(paths, monkeypatch, ids: list[str], args: list[str]) -> int:
    """One nightly run: refresh KEV from MIRROR serving ``ids``, then scan."""
    from boxmunge.commands import security_actions, security_kev
    from boxmunge.cve.kev import load_kev

    paths.config_file.write_text(paths.config_file.read_text() + f"kev:\n  sources: [{MIRROR}]\n")
    body = json.dumps({"dateReleased": datetime.now(timezone.utc).isoformat(),
                       "vulnerabilities": [{"cveID": c} for c in ids]}).encode()
    monkeypatch.setattr(kev_refresh, "_open", lambda req: _Resp(body))
    monkeypatch.setattr(security_kev, "refresh_kev", refresh_kev)
    monkeypatch.setattr(security_kev, "load_kev", load_kev)
    monkeypatch.setattr(security_scan_core, "load_kev", load_kev)
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    rc = security_actions.cmd_security_scan(args, paths)
    paths.config_file.write_text(paths.config_file.read_text().split("kev:\n")[0])
    return rc


@pytest.fixture
def fleet_box(tmp_path, monkeypatch):
    """'demo' quarantined for _CVE (balanced) and 'other', both registered;
    the cache still lists _CVE: the next refresh withdraws it."""
    paths = make_box(tmp_path, projects=("demo", "other"), security={"posture": "balanced"})
    monkeypatch.setattr(security_scan_core, "scan_image",
                        lambda ref, timeout: scan_result(ref, [CRIT]))
    monkeypatch.setattr(quarantine_lift, "prepare_caddy_config", render_site)
    monkeypatch.setattr(quarantine_lift, "prepare_compose_override",
                        lambda p, m, component=None: None)
    paths.docker = Docker(monkeypatch)
    seed_quarantine(paths)
    _catalog(paths, _ids(1400) + [_CVE])
    return paths, Pushover(monkeypatch, paths)


def test_a_project_locked_during_the_withdrawing_run_is_held_next_night(
        fleet_box, monkeypatch) -> None:
    from boxmunge.fileutil import project_lock
    paths, pushover = fleet_box
    with project_lock("demo", paths):
        _fleet(paths, monkeypatch, _ids(1400), [])  # withdraws _CVE; 'demo' skipped
    assert _CVE in load_withdrawals(paths) and is_quarantined("demo", paths)
    _fleet(paths, monkeypatch, _ids(1400), [])  # next night: nothing withdrawn now
    assert is_quarantined("demo", paths)
    assert "compose_up" not in paths.docker.calls
    assert _sent(pushover, HELD) and not _sent(pushover, LIFTED)


def test_a_run_scanning_only_another_project_then_a_nightly_scan_holds(
        fleet_box, monkeypatch) -> None:
    paths, pushover = fleet_box
    _fleet(paths, monkeypatch, _ids(1400), ["other"])  # refreshes KEV for the whole box
    _fleet(paths, monkeypatch, _ids(1400), [])
    assert is_quarantined("demo", paths)
    assert _sent(pushover, HELD) and not _sent(pushover, LIFTED)



# ---- another withdrawn CVE in the same images (the quarantine's own is fixed) ----

_OTHER = "CVE-2026-0002"


def _kev_listing(*extra: str) -> KevCatalog:
    now = datetime.now(timezone.utc)
    return KevCatalog(frozenset(_ids(1400)) | frozenset(extra), now, now, MIRROR)


def test_fixing_the_quarantines_cve_does_not_lift_past_another_withdrawn_one(
        tmp_path, monkeypatch) -> None:
    """Quarantined for KEV CVE A; the images also have KEV CVE B; a source
    withdraws B; the operator fixes A. B is still in the images, so the
    quarantine is held, not lifted."""
    paths = make_box(tmp_path, security={"posture": "balanced"})
    paths.found = [CRIT, finding(_OTHER, pkg="zlib")]
    monkeypatch.setattr(security_scan_core, "scan_image",
                        lambda ref, timeout: scan_result(ref, paths.found))
    monkeypatch.setattr(quarantine_lift, "prepare_caddy_config", render_site)
    monkeypatch.setattr(quarantine_lift, "prepare_compose_override",
                        lambda p, m, component=None: None)
    paths.docker = Docker(monkeypatch)
    pushover = Pushover(monkeypatch, paths)
    seed_quarantine(paths)
    _catalog(paths, _ids(1400) + [_CVE, _OTHER])
    _refresh(paths, monkeypatch, _ids(1400) + [_CVE])  # withdraws B only
    paths.found = [finding(_OTHER, pkg="zlib")]  # A fixed
    scan_one_project(paths, "demo", in_grace=False, kev=_kev_listing(_CVE))
    assert is_quarantined("demo", paths)
    [(title, body, priority)] = _sent(pushover, HELD)
    assert _OTHER in title and priority == 1

    # Resume accepts B for this project; a later quarantine is not held for it.
    _catalog(paths, _ids(1400) + [_CVE])
    assert security_resume_locked(paths, "demo") == 0
    assert load_withdrawals(paths)[_OTHER].accepted == frozenset({"demo"})
    seed_quarantine(paths)
    scan_one_project(paths, "demo", in_grace=False, kev=_kev_listing(_CVE))
    assert not is_quarantined("demo", paths)


def test_the_gate_holds_a_release_with_another_withdrawn_cve(tmp_path, monkeypatch) -> None:
    gate_box = Box(tmp_path, monkeypatch)
    paths = gate_box.paths
    _catalog(paths, _ids(1400) + [_CVE, _OTHER])
    _refresh(paths, monkeypatch, _ids(1400) + [_CVE])  # withdraws B only
    gate_box.findings["postgres@sha256:" + "b" * 64] = (finding(_OTHER, pkg="zlib"),)
    with pytest.raises(gate.QuarantineRefused) as e:
        gate_box.clear(MANIFEST)
    assert f"still contains {_OTHER} (catalog from {MIRROR})" in str(e.value)
