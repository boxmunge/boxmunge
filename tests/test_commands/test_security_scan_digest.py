# SPDX-License-Identifier: Apache-2.0
"""A fleet scan sends one quiet digest for its low-urgency findings; urgent
alerts stay immediate; a single-project scan sends at once."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from boxmunge.commands import security_actions, security_scan_core
from boxmunge.commands.security_actions import cmd_security_scan
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.scanner import Severity
from tests.test_commands.cve_helpers import (
    Docker, Pushover, finding, make_box, scan_result, write_project,
)

_XZ = "CVE-2024-3094"


@pytest.fixture
def fleet(tmp_path, monkeypatch, fake_containers):
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    Docker(monkeypatch)
    for name in ("aaa", "bbb"):
        fake_containers.run(name, "web", "sha256:" + "a" * 64,
                            repo_digests=(f"{name}-web@sha256:{'a' * 64}",))

    def build(posture: str, findings):
        paths = make_box(tmp_path, projects=("aaa", "bbb"),
                         security={"posture": posture})
        monkeypatch.setattr(security_scan_core, "scan_image",
                            lambda ref, timeout: scan_result(ref, findings))
        return paths, Pushover(monkeypatch, paths)
    return build


def test_fleet_sends_one_quiet_digest_not_one_push_per_project(fleet):
    paths, pushover = fleet("strict", [finding("CVE-2026-0001", sev=Severity.LOW)])
    assert cmd_security_scan([], paths) == 0
    [(title, body, priority)] = pushover.sent
    assert priority == -1 and "Nightly CVE scan" in title
    assert "aaa: 1 new, highest Low" in body and "bbb: 1 new, highest Low" in body


def test_fleet_at_balanced_sends_nothing_for_informational(fleet):
    paths, pushover = fleet("balanced", [finding("CVE-2026-0001", sev=Severity.LOW)])
    assert cmd_security_scan([], paths) == 0
    assert pushover.sent == []


def test_single_project_scan_sends_immediately_not_a_digest(fleet):
    paths, pushover = fleet("strict", [finding("CVE-2026-0001", sev=Severity.LOW)])
    assert cmd_security_scan(["aaa"], paths) == 0
    [(title, _, priority)] = pushover.sent
    assert priority == 0 and "1 new CVE finding" in title


def test_urgent_is_immediate_and_not_repeated_in_the_digest(
        tmp_path, monkeypatch, fake_containers):
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(security_actions, "refresh_kev_and_alert",
                        lambda paths, n: KevCatalog(frozenset({_XZ}), now, now, "test"))
    Docker(monkeypatch)
    for name in ("aaa", "bbb", "ccc"):
        fake_containers.run(name, "web", "sha256:" + "a" * 64,
                            repo_digests=(f"{name}-web@sha256:{'a' * 64}",))
    # aaa: relaxed, fixable KEV (urgent, every scan); bbb, ccc: strict, low finding.
    paths = make_box(tmp_path, projects=("aaa",), security={"posture": "relaxed"})
    for name in ("bbb", "ccc"):
        write_project(paths, name)
    (paths.state / "projects.txt").write_text("aaa\nbbb\nccc\n")
    monkeypatch.setattr(
        security_scan_core, "scan_image",
        lambda ref, timeout: scan_result(
            ref, [finding(_XZ, fix="5.6.1-2")] if ref.startswith("aaa")
            else [finding("CVE-2026-0001", sev=Severity.LOW)]))
    pushover = Pushover(monkeypatch, paths)
    cmd_security_scan([], paths)
    [(utitle, _, uprio), (dtitle, dbody, dprio)] = pushover.sent
    assert uprio == 1 and "ACTIVELY EXPLOITED" in utitle
    assert dprio == -1 and "Nightly CVE scan" in dtitle
    assert "bbb: 1 new" in dbody and "ccc: 1 new" in dbody and "aaa" not in dbody


def test_no_digest_when_balanced_drops_the_only_content(fleet):
    paths, pushover = fleet("balanced", [finding("CVE-2026-0001", sev=Severity.LOW)])
    cmd_security_scan([], paths)
    assert not [t for t in pushover.titles() if "Nightly CVE scan" in t]
