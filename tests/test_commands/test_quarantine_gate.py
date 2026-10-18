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
        # As the scratch overlay resolves (builds under candidate names).
        self.services = {"web": {"image": candidate_name("demo", "web")},
                         "db": {"image": "postgres:16"}, "cache": {"image": "redis:7"}}
        monkeypatch.setattr(gate, "resolved_services", lambda target: ({}, self.services))
        monkeypatch.setattr(gate.docker_containers, "local_image", self.images.get)
        monkeypatch.setattr(gate, "resolve_deployed_config",
                            lambda *a, **k: {"services": {n: {} for n in self.services}})
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


def _as_switched(box) -> None:
    """The release's real overlay: builds under their own names."""
    box.services = {**box.services, "web": {"image": "boxmunge.invalid/demo/web"}}


def test_require_unchanged_accepts_the_release_as_scanned(box) -> None:
    clearance = box.clear()
    _as_switched(box)
    gate.require_unchanged(box.paths, clearance)


def test_require_unchanged_refuses_a_moved_name(box) -> None:
    clearance = box.clear()
    _as_switched(box)
    box.images["postgres:16"] = LocalImage("sha256:" + "d" * 64, ())
    with pytest.raises(gate.QuarantineRefused) as e:
        gate.require_unchanged(box.paths, clearance)
    assert "service db would start postgres:16 (sha256:ddd" in str(e.value)


def test_require_unchanged_refuses_a_release_its_hook_rewrote(box) -> None:
    clearance = box.clear()
    _as_switched(box)
    box.services = {**box.services, "db": {"image": "postgres:17"}, "extra": {"image": "x:1"}}
    with pytest.raises(gate.QuarantineRefused) as e:
        gate.require_unchanged(box.paths, clearance)
    text = str(e.value)
    assert "service db would start postgres:17" in text
    assert "service extra was not in the release that was scanned" in text


def test_a_service_reusing_a_build_is_scanned_as_the_new_build(box) -> None:
    box.services["worker"] = {"image": "boxmunge.invalid/demo/web"}
    clearance = box.clear()
    assert clearance.images["worker"] == ("boxmunge.invalid/demo/web", "sha256:" + "a" * 64)
    assert box.scanned.count("sha256:" + "a" * 64) == 1  # one image, scanned once
    _as_switched(box)
    gate.require_unchanged(box.paths, clearance)


def test_a_corrupt_quarantine_record_refuses(box) -> None:
    box.paths.project_quarantine_state("demo").write_text(json.dumps({"cve_id": 7}))
    with pytest.raises(gate.QuarantineRefused) as e:
        box.clear()
    assert "is corrupt" in str(e.value) and box.scanned == []


def _container(name, service, image_id, oneoff=False, running=True):
    from boxmunge.docker_containers import ProjectContainer
    return ProjectContainer(name=name, service=service, image_id=image_id, repo_digests=(),
                            running=running, health=None, oneoff=oneoff, exit_code=None,
                            restart_policy="no")


def test_the_lift_needs_every_running_container_on_a_scanned_image(box, monkeypatch,
                                                                   capsys) -> None:
    clearance = box.clear()
    running = [_container("demo-web-1", "web", "sha256:" + "a" * 64),
               _container("demo-db-1", "db", "sha256:" + "e" * 64),  # pulled anew by `up`
               _container("demo-tool-run-1", "tool", "sha256:f", oneoff=True),
               _container("demo-dev-1", "dev", "sha256:old", running=False)]
    monkeypatch.setattr(gate.docker_containers, "project_containers", lambda p: running)
    with pytest.raises(gate.QuarantineError) as e:
        gate._verify_running(box.paths, clearance, "deploy")
    assert str(e.value) == f"demo-db-1 runs sha256:{'e' * 64}, not a scanned image"
    running[1] = _container("demo-db-1", "db", "sha256:" + "b" * 64)
    # The stopped container on an unscanned image is left held, and named.
    assert gate._verify_running(box.paths, clearance, "deploy") == {
        "demo-web-1": "web", "demo-db-1": "db"}
    assert 'keep restart policy "no": demo-dev-1' in capsys.readouterr().out


def test_held_containers_get_their_release_policy(box) -> None:
    box.services = {"web": {"image": "w", "restart": "always"}, "db": {"image": "d"},
                    "job": {"image": "j", "deploy": {"restart_policy": {
                        "condition": "on-failure", "max_attempts": 3}}}}
    assert gate._release_policies(box.paths, "demo", {
        "demo-web-1": "web", "demo-db-1": "db", "demo-job-1": "job"}) == {
        "demo-web-1": "always", "demo-db-1": "no", "demo-job-1": "on-failure:3"}
    with pytest.raises(gate.QuarantineError, match="no longer in the release"):
        gate._release_policies(box.paths, "demo", {"demo-gone-1": "gone"})


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


def test_a_refused_switch_puts_the_maintenance_page_back(box, monkeypatch, capsys) -> None:
    """The release's configs replaced the maintenance site; a refusal after
    that re-asserts the quarantine at once rather than at the next scan."""
    from boxmunge.commands import deploy_tree
    from boxmunge.commands.release_config import ReleaseDecision
    from boxmunge.release_txn import advance, open_txn
    reasserted = []
    monkeypatch.setattr(gate, "reassert_quarantine",
                        lambda project, paths_, **kw: reasserted.append((project, kw)))
    monkeypatch.setattr(deploy_tree, "generate_release_config", lambda *a: None)
    monkeypatch.setattr(deploy_tree, "run_pre_deploy_hook", lambda *a: 0)
    clearance = box.clear()
    box.services = {**box.services, "db": {"image": "postgres:17"}}  # the hook changed it
    txn = open_txn(box.paths, "demo", source="bundle", ref="demo-r2", replaced_ref=None,
                   staged_id=None, snapshot="")
    for phase in ("previous_kept", "installed"):
        txn = advance(box.paths, "demo", txn, phase)
    req = deploy_tree.TreeDeploy(tree=None, ref="demo-r2", source="bundle", manifest=MANIFEST)
    assert deploy_tree.switch_and_close("demo", box.paths, req, txn,
                                        ReleaseDecision({}, clearance)) == 1
    err = capsys.readouterr().err
    assert "service db would start postgres:17" in err
    assert "its maintenance page is back" in err
    ((project, kw),) = reasserted
    assert project == "demo" and kw["hosts"] == ["demo.example.com"]
