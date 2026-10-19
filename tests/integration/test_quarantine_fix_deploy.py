# SPDX-License-Identifier: Apache-2.0
"""Deploying a fix to a CVE-quarantined project, on a real daemon.

A project with a build service (app) and a registry service (side) is
deployed, then quarantined for real (maintenance page, stop, restart
policies held at "no"). Trivy is the only stub: an image is vulnerable
when its `vulnerable` label says so, so the scan must see the release's
own candidate images. A paused project is refused; a vulnerable release
and a failed image scan are refused with nothing changed and no candidate
left; a clean release deploys and lifts the quarantine, giving the held
policy back to the container it did not recreate and leaving the
recreated one with its release's own.
"""
from __future__ import annotations

import subprocess
import uuid
from unittest.mock import patch

import pytest
import yaml

from boxmunge.commands import quarantine_gate
from boxmunge.cve.policy import Disposition, FindingDisposition
from boxmunge.cve.quarantine import is_quarantined, quarantine_project
from boxmunge.cve.scanner import ScannerError, Severity
from boxmunge.docker import project_restart_policies, set_restart_policy
from boxmunge.pause import clear_paused_state, write_paused_state
from tests.integration import nonroot_cases as nc
from tests.integration.conftest import skip_no_docker
from tests.test_commands.cve_helpers import finding, scan_result

pytestmark = [pytest.mark.integration, skip_no_docker]

CVE = "CVE-2026-4242"
NOBODY = {"user": "65534:65534"}
BALANCED = {"posture": "balanced", "dangerously_disable_quarantine": False, "runtimes": None}


def _bundle(p: str, vulnerable: str, app_restart: str, *,
            read_only: bool = False) -> dict[str, str]:
    services = {
        "app": {"build": ".", "command": nc.SLEEP, "restart": app_restart},
        "side": {"image": nc.BUSYBOX, "command": nc.SLEEP, "restart": "always"},
    }
    if read_only:  # what dangerously_disable_quarantine requires
        for svc in services.values():
            svc["read_only"] = True
    return nc.bundle(p, services, declare={"app": NOBODY, "side": NOBODY}, files={
        "Dockerfile": f"FROM {nc.BUSYBOX}\nLABEL vulnerable={vulnerable}\n"
                      f"RUN echo {uuid.uuid4().hex} > /release\n"})


def _label(ref: str) -> str:
    return subprocess.run(
        ["docker", "image", "inspect", "--format", '{{index .Config.Labels "vulnerable"}}',
         ref], capture_output=True, text=True, check=True).stdout.strip()


class Trivy:
    def __init__(self) -> None:
        self.fail = False
        self.scanned: list[str] = []

    def __call__(self, ref: str, timeout=None):
        self.scanned.append(ref)
        if self.fail and _label(ref) == "no":
            raise ScannerError("trivy timed out")
        return scan_result(ref, (finding(CVE),) if _label(ref) == "yes" else ())


def _containers(p: str) -> dict[str, tuple[str, bool]]:
    """{name: (container ID, running)} of the project's containers."""
    out = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={p}",
         "--format", "{{.Names}} {{.ID}} {{.State}}"],
        capture_output=True, text=True, check=True).stdout
    return {n: (i, s == "running") for n, i, s in (line.split() for line in out.splitlines())}


def _candidates(p: str) -> list[str]:
    return subprocess.run(
        ["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}", "--filter",
         f"reference=boxmunge.invalid/{p}/*:boxmunge-candidate"],
        capture_output=True, text=True, check=True).stdout.split()


def _quarantine(paths, p: str) -> None:
    headline = FindingDisposition(
        finding=finding(CVE), base_severity=Severity.CRITICAL, hardening_penalty=0,
        effective_severity=Severity.CRITICAL, disposition=Disposition.QUARANTINE,
        suppression=None, explanation="critical")
    quarantine_project(p, paths, project_dir=paths.project_dir(p),
                       hosts=[f"{p}.example.com"],
                       compose_files=["compose.yml", "compose.boxmunge.yml"],
                       headline=headline, image_ref="app", policy=BALANCED)


def _stub_scanner(monkeypatch) -> Trivy:
    trivy = Trivy()
    monkeypatch.setattr("boxmunge.commands.security_scan_core.scan_image", trivy)
    monkeypatch.setattr(quarantine_gate, "refresh_db", lambda: None)
    # The suite keeps restart-policy holds off the daemon; these tests are about them.
    monkeypatch.setattr("boxmunge.restart_hold.project_restart_policies",
                        project_restart_policies)
    monkeypatch.setattr("boxmunge.restart_hold.set_restart_policy", set_restart_policy)
    return trivy


def _refused_unchanged(paths, p, capsys, files, before) -> str:
    rc, out = nc.deploy(paths, p, files, capsys)
    assert rc == 1, out
    assert is_quarantined(p, paths)
    assert _containers(p) == before  # nothing recreated or started
    assert set(project_restart_policies(project_name=p).values()) == {"no"}
    assert _candidates(p) == []
    return out


def test_deploying_a_fix_to_a_quarantined_project(int_paths, capsys, monkeypatch) -> None:
    p = f"bmqf{uuid.uuid4().hex[:8]}"
    trivy = _stub_scanner(monkeypatch)
    try:
        with patch("boxmunge.cve.quarantine.caddy_reload"):
            rc, out = nc.deploy(int_paths, p, _bundle(p, "yes", "unless-stopped"), capsys)
            assert rc == 0, out
            _quarantine(int_paths, p)
            before = _containers(p)
            assert len(before) == 2 and not any(r for _i, r in before.values())

            write_paused_state(p, int_paths)
            out = _refused_unchanged(int_paths, p, capsys,
                                     _bundle(p, "no", "always"), before)
            assert "paused and CVE-quarantined" in out and trivy.scanned == []
            clear_paused_state(p, int_paths)

            out = _refused_unchanged(int_paths, p, capsys,
                                     _bundle(p, "yes", "always"), before)
            assert f"{CVE} (Critical) in openssl 1, service app" in out
            assert "quarantine stays in place" in out

            trivy.fail = True
            out = _refused_unchanged(int_paths, p, capsys,
                                     _bundle(p, "no", "always"), before)
            assert "scan failed" in out
            trivy.fail = False

            rc, out = nc.deploy(int_paths, p, _bundle(p, "no", "always"), capsys)
            assert rc == 0, out
        assert not is_quarantined(p, int_paths)
        assert f"lifted by deploying {p}-" in out
        after = _containers(p)
        assert all(running for _i, running in after.values())
        side = next(n for n in after if "side" in n)
        app = next(n for n in after if "app" in n)
        assert after[side][0] == before[side][0]  # not recreated: its held policy is back
        assert after[app][0] != before[app][0]
        assert project_restart_policies(project_name=p) == {side: "always", app: "always"}
        assert _label(f"boxmunge.invalid/{p}/app") == "no"
        assert _candidates(p) == []
    finally:
        nc.teardown(int_paths, p)


def test_a_release_that_relaxes_the_policy_lifts_and_says_so(int_paths, capsys,
                                                            monkeypatch) -> None:
    """The images still carry the finding: the release clears the quarantine
    only by opting out of it, and the lift reports that, not a fix."""
    p = f"bmqr{uuid.uuid4().hex[:8]}"
    _stub_scanner(monkeypatch)
    sent = []
    monkeypatch.setattr(quarantine_gate, "notify",
                        lambda paths, title, body, **kw: sent.append((title, body, kw)))
    try:
        with patch("boxmunge.cve.quarantine.caddy_reload"):
            rc, out = nc.deploy(int_paths, p, _bundle(p, "yes", "unless-stopped"), capsys)
            assert rc == 0, out
            _quarantine(int_paths, p)
            files = _bundle(p, "yes", "always", read_only=True)
            manifest = yaml.safe_load(files["manifest.yml"])
            manifest["security"] = {"dangerously_disable_quarantine": True}
            files["manifest.yml"] = yaml.safe_dump(manifest)
            rc, out = nc.deploy(int_paths, p, files, capsys)
            assert rc == 0, out
        assert not is_quarantined(p, int_paths)
        assert "by relaxing the security policy (dangerously_disable_quarantine turned on)" in out
        assert "images were not shown to be fixed" in out
        assert f"Still running at risk: {CVE} (Critical) in openssl 1, service app" in out
        ((title, body, kw),) = sent
        assert "relaxing the security policy" in title and kw["priority"] == 1
        assert "not shown to be fixed" in body
    finally:
        nc.teardown(int_paths, p)
