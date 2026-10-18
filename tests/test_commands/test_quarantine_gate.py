# SPDX-License-Identifier: Apache-2.0
"""The scan that lets a CVE-quarantined project's release ship as its fix
(commands/quarantine_gate). The real scan, policy and KEV code run; only
Docker (the resolved services, the local image store) and Trivy are stubbed.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from boxmunge.commands import quarantine_gate as gate
from boxmunge.commands.deploy_images import candidate_name
from boxmunge.cve.scanner import ScannerError, TrivyNotInstalledError
from boxmunge.docker_containers import LocalImage
from boxmunge.release_target import production_target
from tests.test_commands.cve_helpers import finding, make_box, scan_result, seed_quarantine

KEV_CVE = "CVE-2026-7777"
MANIFEST = {"project": "demo", "hosts": ["demo.example.com"], "services": {}}


class Box:
    """A quarantined project whose release has a build (web), a registry
    image (db) and a held-back registry image pulled again (cache)."""

    def __init__(self, tmp_path, monkeypatch) -> None:
        self.paths = make_box(tmp_path)
        seed_quarantine(self.paths)
        self.images = {
            candidate_name("demo", "web"): LocalImage("sha256:" + "a" * 64, ()),
            "boxmunge.invalid/demo/web": LocalImage("sha256:" + "a" * 64, ()),
            "postgres:16": LocalImage("sha256:" + "b" * 64, ("postgres@sha256:" + "b" * 64,)),
            candidate_name("demo", "cache"): LocalImage("sha256:" + "c" * 64, ()),
            "redis:7": LocalImage("sha256:" + "c" * 64, ()),
        }
        self.findings: dict[str, tuple] = {}
        self.failing: set[str] = set()
        self.scanned: list[str] = []
        services = {"web": {"image": candidate_name("demo", "web")},
                    "db": {"image": "postgres:16"}, "cache": {"image": "redis:7"}}
        monkeypatch.setattr(gate, "resolved_services", lambda target: ({}, services))
        monkeypatch.setattr(gate.docker_containers, "local_image", self.images.get)
        monkeypatch.setattr(gate, "resolve_deployed_config",
                            lambda *a, **k: {"services": {n: {} for n in services}})
        monkeypatch.setattr(gate, "refresh_db", lambda: None)
        monkeypatch.setattr("boxmunge.commands.security_scan_core.scan_image", self._scan)

    def _scan(self, ref, timeout=None):
        self.scanned.append(ref)
        if ref in self.failing:
            raise ScannerError("trivy exploded")
        return scan_result(ref, self.findings.get(ref, ()))

    def kev(self, *cves: str) -> None:
        self.paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
        self.paths.kev_catalog.write_text(json.dumps({
            "fetched_at": datetime.now(timezone.utc).isoformat(), "cve_ids": list(cves)}))

    def clear(self, manifest=MANIFEST):
        return gate.clear_release(self.paths, production_target(self.paths, "demo"), manifest)


@pytest.fixture
def box(tmp_path, monkeypatch) -> Box:
    return Box(tmp_path, monkeypatch)


def test_clean_release_is_cleared_with_the_names_it_starts_under(box) -> None:
    clearance = box.clear()
    assert clearance.cve_id == "CVE-2026-0001"
    assert clearance.images == {
        "web": ("boxmunge.invalid/demo/web", "sha256:" + "a" * 64),
        "db": ("postgres:16", "sha256:" + "b" * 64),
        "cache": ("redis:7", "sha256:" + "c" * 64),
    }
    # Every service's image, by the exact image (digest or ID), candidates
    # rather than the names production's containers still run.
    assert sorted(box.scanned) == sorted(["sha256:" + "a" * 64, "postgres@sha256:" + "b" * 64,
                                          "sha256:" + "c" * 64])


def test_quarantine_level_finding_refuses_naming_cve_package_and_image(box) -> None:
    box.findings["postgres@sha256:" + "b" * 64] = (finding("CVE-2026-1234"),)
    with pytest.raises(gate.QuarantineRefused) as e:
        box.clear()
    text = str(e.value)
    assert "CVE-2026-1234 (Critical) in openssl 1, service db (image postgres@sha256:" in text
    assert "no fixed version is published yet" in text
    assert "quarantine stays in place" in text and "nothing was started" in text


def test_fixable_kev_finding_names_the_fix(box) -> None:
    box.kev(KEV_CVE)
    box.findings["sha256:" + "c" * 64] = (finding(KEV_CVE, fix="7.0.9", pkg="libc"),)
    with pytest.raises(gate.QuarantineRefused) as e:
        box.clear()
    assert "in libc 1, service cache" in str(e.value)
    assert "fixed in 7.0.9: update the package, or rebuild" in str(e.value)


def test_kev_finding_refuses_whatever_the_release_posture(box) -> None:
    box.kev(KEV_CVE)
    from boxmunge.cve.scanner import Severity
    box.findings["sha256:" + "a" * 64] = (finding(KEV_CVE, sev=Severity.LOW),)
    relaxed = {**MANIFEST, "security": {"posture": "relaxed"}}
    with pytest.raises(gate.QuarantineRefused) as e:
        box.clear(relaxed)
    assert KEV_CVE in str(e.value) and "CISA KEV" in str(e.value)


def test_the_release_manifest_sets_the_policy(box) -> None:
    """The deployed manifest has no opt-out; the release's does."""
    box.findings["postgres@sha256:" + "b" * 64] = (finding("CVE-2026-1234"),)
    opted_out = {**MANIFEST, "security": {"dangerously_disable_quarantine": True}}
    assert box.clear(opted_out).cve_id == "CVE-2026-0001"


def test_failed_image_scan_refuses(box) -> None:
    box.failing.add("postgres@sha256:" + "b" * 64)
    with pytest.raises(gate.QuarantineRefused) as e:
        box.clear()
    assert "scan failed" in str(e.value) and "did not cover every image" in str(e.value)


def test_budget_skip_refuses(box, monkeypatch) -> None:
    monkeypatch.setattr("boxmunge.commands.security_scan_core._PROJECT_BUDGET_SECONDS", 0)
    with pytest.raises(gate.QuarantineRefused) as e:
        box.clear()
    assert "budget" in str(e.value)


def test_image_missing_from_the_store_refuses(box) -> None:
    del box.images["postgres:16"]
    with pytest.raises(gate.QuarantineRefused) as e:
        box.clear()
    assert "service 'db'" in str(e.value) and "not in the local image store" in str(e.value)


def test_missing_trivy_refuses(box, monkeypatch) -> None:
    def missing():
        raise TrivyNotInstalledError("trivy is not installed")
    monkeypatch.setattr(gate, "refresh_db", missing)
    with pytest.raises(gate.QuarantineRefused) as e:
        box.clear()
    assert "trivy is not installed" in str(e.value)


def test_require_unchanged_refuses_a_moved_name(box) -> None:
    clearance = box.clear()
    gate.require_unchanged(clearance)
    box.images["postgres:16"] = LocalImage("sha256:" + "d" * 64, ())
    with pytest.raises(gate.QuarantineRefused) as e:
        gate.require_unchanged(clearance)
    assert "service db: postgres:16 no longer names the image that was scanned" in str(e.value)


def test_replace_release_starts_nothing_unscanned_while_quarantined(box, monkeypatch,
                                                                    capsys) -> None:
    """Every path into the start passes the scan; one that did not is
    refused rather than started."""
    from boxmunge.commands import deploy
    started = []
    monkeypatch.setattr(deploy, "_start_and_verify", lambda *a: started.append(a) or 0)
    assert deploy.replace_release("demo", box.paths, MANIFEST, "demo-r2", None) == 1
    assert "were not scanned; nothing was started" in capsys.readouterr().err
    assert started == []
