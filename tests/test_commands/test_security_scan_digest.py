# SPDX-License-Identifier: Apache-2.0
"""A fleet scan sends one quiet digest for its low-urgency findings; urgent
alerts stay immediate; a single-project scan sends at once."""
from __future__ import annotations

import pytest

from boxmunge.commands import security_actions, security_scan_core
from boxmunge.commands.security_actions import cmd_security_scan
from boxmunge.cve.scanner import Severity
from tests.test_commands.cve_helpers import (
    Docker, Pushover, finding, make_box, scan_result,
)


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
