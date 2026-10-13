# SPDX-License-Identifier: Apache-2.0
"""Fleet scan robustness: failures are isolated, alerted, and fail the exit
code (audit B-11, B-12)."""
from __future__ import annotations

import pytest
import yaml

from boxmunge.commands import security_actions, security_scan_core, security_scan_inputs
from boxmunge.commands.security_actions import cmd_security_scan
from boxmunge.cve.scanner import ScannerError
from tests.test_commands.cve_helpers import Pushover, make_box, scan_result


@pytest.fixture
def scanned(monkeypatch):
    """Stub Trivy and container digests; record which images were scanned."""
    seen: list[str] = []
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    monkeypatch.setattr(security_scan_inputs, "container_image_digest", lambda c: None)

    def scan(ref, timeout):
        seen.append(ref)
        if "broken" in ref:
            raise ScannerError("registry unreachable")
        return scan_result(ref)

    monkeypatch.setattr(security_scan_core, "scan_image", scan)
    return seen


def _set_security(paths, project: str, block) -> None:
    path = paths.project_manifest(project)
    manifest = yaml.safe_load(path.read_text())
    manifest["security"] = block
    path.write_text(yaml.safe_dump(manifest))


def _failure_alerts(pushover: Pushover) -> list[tuple[str, str, int]]:
    return [s for s in pushover.sent if "CVE scan incomplete" in s[0]]


def test_corrupt_scan_state_does_not_stop_the_fleet(tmp_path, monkeypatch, scanned):
    """Audit B-12 script C: a truncated prior state is treated as no prior."""
    paths = make_box(tmp_path, projects=("aaa", "bbb", "ccc"))
    pushover = Pushover(monkeypatch, paths)
    state = paths.project_scan_state("aaa")
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text("{truncated")
    assert cmd_security_scan([], paths) == 0
    assert scanned == ["aaa-web:1", "bbb-web:1", "ccc-web:1"]
    assert _failure_alerts(pushover) == []
    # The bad file was replaced by this scan's state.
    assert state.read_text().startswith("{\n")


@pytest.mark.parametrize("block, needle", [
    ({"posture": "balanaced"}, "unknown posture"),
    ("strict", "security: must be a mapping"),
    ({"dangerously_disable_quarantine": "yes"}, "must be true or false"),
])
def test_one_malformed_manifest_is_reported_and_the_rest_scanned(
    tmp_path, monkeypatch, scanned, capsys, block, needle,
):
    """Audit B-12 script D: the bad project fails alone, loudly."""
    paths = make_box(tmp_path, projects=("aaa", "bbb"))
    pushover = Pushover(monkeypatch, paths)
    _set_security(paths, "aaa", block)
    rc = cmd_security_scan([], paths)
    out = capsys.readouterr().out
    assert rc == 1
    assert scanned == ["bbb-web:1"]
    assert "aaa: ERROR" in out and needle in out
    [(title, body, priority)] = _failure_alerts(pushover)
    assert priority == 1
    assert "1 project not fully scanned" in title
    assert "- aaa:" in body and needle in body


def test_partial_image_failure_exits_1_and_alerts(tmp_path, monkeypatch, scanned, capsys):
    """Audit B-11 script E: one unscannable image is a failure, not exit 0."""
    paths = make_box(
        tmp_path, services=("web", "worker"),
        images={"web": "demo-web:1", "worker": "broken-worker:1"},
    )
    pushover = Pushover(monkeypatch, paths)
    rc = cmd_security_scan([], paths)
    assert rc == 1
    assert "INCOMPLETE" in capsys.readouterr().out
    [(_, body, priority)] = _failure_alerts(pushover)
    assert priority == 1
    assert "image broken-worker:1: scan failed" in body


def test_unidentifiable_service_is_a_partial_failure(tmp_path, monkeypatch, scanned):
    paths = make_box(tmp_path, services=("web", "worker"), images={"web": "demo-web:1"})
    pushover = Pushover(monkeypatch, paths)
    assert cmd_security_scan([], paths) == 1
    [(_, body, _)] = _failure_alerts(pushover)
    assert "service 'worker': no image could be identified" in body


def test_single_project_scan_failure_also_alerts(tmp_path, monkeypatch, scanned):
    paths = make_box(tmp_path, images={"web": "broken-web:1"})
    pushover = Pushover(monkeypatch, paths)
    assert cmd_security_scan(["demo"], paths) == 1
    assert len(_failure_alerts(pushover)) == 1


def test_failures_across_projects_make_one_alert(tmp_path, monkeypatch, scanned):
    paths = make_box(tmp_path, projects=("aaa", "bbb"), images={"web": "broken-web:1"})
    pushover = Pushover(monkeypatch, paths)
    assert cmd_security_scan([], paths) == 1
    [(title, body, _)] = _failure_alerts(pushover)
    assert "2 projects not fully scanned" in title
    assert "- aaa:" in body and "- bbb:" in body


def test_clean_fleet_sends_no_failure_alert(tmp_path, monkeypatch, scanned):
    paths = make_box(tmp_path, projects=("aaa", "bbb"))
    pushover = Pushover(monkeypatch, paths)
    assert cmd_security_scan([], paths) == 0
    assert _failure_alerts(pushover) == []
