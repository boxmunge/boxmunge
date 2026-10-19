# SPDX-License-Identifier: Apache-2.0
"""The projects of the dev fixture box, and how each is written to disk.

Every file uses the same format the real platform writes, so the observe
handlers read the fixture through exactly the code they use on a box.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from boxmunge.legacy_stage import legacy_staging_state
from boxmunge.paths import BoxPaths
from boxmunge.release import mark_live
from boxmunge.release_txn import advance, open_txn
from boxmunge.staged_release import StagedRelease, slot_dir, write_meta
from boxmunge.ulid import generate_ulid

DEV_DIR = "dev"
_EXIT_CODES = {"ok": 0, "warning": 1, "critical": 2}


def finding(cve: str, severity: str, disposition: str, package: str,
            explanation: str, *, fixed: str | None = None) -> dict[str, Any]:
    """A scan-state finding, with every key cve.scan_state writes."""
    return {
        "cve_id": cve, "base_severity": severity, "effective_severity": severity,
        "hardening_penalty": 0, "disposition": disposition, "explanation": explanation,
        "fix_available": fixed is not None, "fixed_version": fixed, "package": package,
        "primary_url": f"https://cve.example.test/{cve}",
        "title": f"{package}: example vulnerability", "installed_version": "1.0.0-1",
        "attack_vector": "Network", "status": "fixed" if fixed else "affected",
        "pkg_class": "os-pkgs", "pkg_type": "debian", "kev_listed": False,
        "fix_would_quarantine": False,
        "hardening_would_quarantine": False,
    }


@dataclass(frozen=True)
class FixtureProject:
    name: str
    services: tuple[str, ...] = ()
    deploys_hours_ago: tuple[float, ...] = ()   # newest first; empty: pre-registered
    posture: str = "balanced"
    health: str = "ok"
    failure_reason: str = ""
    paused_reason: str | None = None
    quarantine_cve: str | None = None
    staged: bool = False
    install_phase: str | None = None   # an open install (.releases/install.json) at this phase
    legacy_kind: str | None = None      # a stage left by boxmunge 0.10.1 ("bundle")
    findings: tuple[dict[str, Any], ...] = ()
    backups: tuple[tuple[str, float], ...] = ()  # (kind, hours ago)
    smoke: tuple[str, str] = ("ok", "")           # (status, message)


QUARANTINE_CVE = "CVE-2026-32003"

PROJECTS: tuple[FixtureProject, ...] = (
    FixtureProject(
        "shop", ("web", "worker"), deploys_hours_ago=(3, 75), install_phase="installed",
        findings=(
            finding("CVE-2026-31001", "Medium", "informational", "libxml2",
                    "Medium, below the balanced threshold. Reported only."),
            finding("CVE-2026-31002", "High", "ignored_fixed", "openssl",
                    "Fixed in the running image.", fixed="3.0.15-1"),
        ),
        backups=(("predeploy", 3), ("nightly", 6), ("manual", 50)),
    ),
    FixtureProject(
        "blog", ("web",), deploys_hours_ago=(200,), posture="strict",
        paused_reason="Content freeze until the redesign ships", legacy_kind="bundle",
        backups=(("nightly", 30),),
        smoke=("warning", "smoke could not run (infrastructure, not app): "
                          "container blog-web-1 is not running"),
    ),
    FixtureProject(
        "billing", ("api", "db"), deploys_hours_ago=(20,), quarantine_cve=QUARANTINE_CVE,
        findings=(
            finding(QUARANTINE_CVE, "Critical", "quarantine", "libcurl",
                    "Critical, network-reachable, no upstream fix. Meets the balanced "
                    "threshold: quarantine."),
        ),
        backups=(("nightly", 6), ("prerestore", 48)),
        smoke=("warning", "smoke could not run (infrastructure, not app): "
                          "container billing-api-1 is not running"),
    ),
    FixtureProject(
        "wiki", ("web",), deploys_hours_ago=(10, 34), posture="relaxed",
        health="failing", failure_reason="smoke: GET /health returned 503", staged=True,
        backups=(("predeploy", 10), ("nightly", 30)),
        smoke=("warning", "GET /health returned 503"),
    ),
    FixtureProject("newapp"),
)


def iso(moment: datetime) -> str:
    return moment.isoformat()


def ref(name: str, moment: datetime) -> str:
    return f"{name}-{moment:%Y-%m-%dT%H%M%S}"


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def write_project(paths: BoxPaths, project: FixtureProject, now: datetime) -> None:
    """Write one project: manifest, state files, scan, backups, dev data."""
    project_dir = paths.projects / project.name
    project_dir.mkdir(parents=True)
    if not project.deploys_hours_ago:
        return  # pre-registered: a directory without a manifest
    project_id = generate_ulid()
    project_dir.joinpath("manifest.yml").write_text(yaml.safe_dump({
        "schema_version": 3, "id": project_id, "project": project.name,
        "source": "bundle", "hosts": [f"{project.name}.example.test"],
        "services": {
            svc: {"port": 8080, "routes": [{"path": "/"}],
                  "smoke": "boxmunge-scripts/smoke.sh"}
            for svc in project.services
        },
        "security": {"posture": project.posture},
    }, sort_keys=False))
    _write_state(paths, project, project_id, now)
    _write_scan(paths, project, now)
    _write_backups(paths, project, now)
    _write_dev_data(paths, project, now)


def _write_state(paths: BoxPaths, project: FixtureProject, project_id: str,
                 now: datetime) -> None:
    name = project.name
    deploys = [now - timedelta(hours=h) for h in project.deploys_hours_ago]
    write_json(paths.project_deploy_state(name), {
        "project_id": project_id, "current_ref": ref(name, deploys[0]),
        "deployed_at": iso(deploys[0]), "last_started_at": iso(deploys[0]),
        "pre_deploy_snapshot": "",
        "history": [{"ref": ref(name, d), "deployed_at": iso(d), "snapshot": ""}
                    for d in deploys[1:]],
    })
    ok = project.health == "ok"
    write_json(paths.project_health_state(name), {
        "last_check": iso(now - timedelta(minutes=2)), "status": project.health,
        "consecutive_failures": 0 if ok else 3, "alerted": not ok,
        "failure_reason": project.failure_reason,
    })
    if project.staged:
        slot = slot_dir(paths, name)
        (slot / "release").mkdir(parents=True, exist_ok=True)
        write_meta(slot, StagedRelease(
            id="01JF1XTVREST0STAGED0000000", kind="bundle",
            ref=ref(name, now - timedelta(hours=1)), bundle_sha256=None,
            staged_at=iso(now - timedelta(hours=1)), state="ready"))
    if project.install_phase is not None:
        _write_install(paths, name, ref(name, deploys[0]), project.install_phase, now)
    if project.legacy_kind is not None:
        _write_legacy_stage(paths, name, project.legacy_kind, ref(name, deploys[0]), now)
    if project.paused_reason is not None:
        write_json(paths.project_paused_state(name), {
            "paused_at": iso(now - timedelta(hours=26)), "reason": project.paused_reason})
    if project.quarantine_cve is not None:
        write_json(paths.project_quarantine_state(name), {
            "quarantined_at": iso(now - timedelta(hours=5)), "cve_id": project.quarantine_cve,
            "severity": "Critical", "effective_severity": "Critical",
            "explanation": project.findings[0]["explanation"],
            "image_ref": "sha256:" + "b" * 64, "action_complete": True,
        })


def _write_install(paths: BoxPaths, name: str, live: str, phase: str,
                   now: datetime) -> None:
    """A prod-deploy of the inbox's bundle that stopped at `phase`."""
    bundle = f"{name}-{now - timedelta(hours=1):%Y-%m-%dT%H%M%S%f}"
    txn = open_txn(paths, name, source="bundle", ref=bundle, replaced_ref=live,
                   staged_id=None, snapshot="")
    if phase != txn.phase:
        advance(paths, name, txn, phase)


def _write_legacy_stage(paths: BoxPaths, name: str, kind: str, live: str,
                        now: datetime) -> None:
    """What 0.10.1 left after staging a bundle two days ago: production's
    release kept in .releases/prestage/, the staged one in the project dir
    and live.json."""
    if kind != "bundle":
        raise ValueError(f"the fixture writes only a bundle legacy stage, not {kind!r}")
    staged_at = now - timedelta(days=2)
    staged = ref(name, staged_at)
    releases = paths.project_releases(name)
    (releases / "prestage" / "release").mkdir(parents=True)
    meta = releases / "prestage" / "meta.json"
    write_json(meta, {"ref": live})
    os.utime(meta, (staged_at.timestamp(), staged_at.timestamp()))
    mark_live(paths, name, staged)
    write_json(legacy_staging_state(paths, name), {"active": True, "ref": staged})


def _write_scan(paths: BoxPaths, project: FixtureProject, now: datetime) -> None:
    write_json(paths.project_scan_state(project.name), {
        "scanned_at": iso(now - timedelta(hours=5)),
        "decisions": [{
            "image_ref": f"registry.example.test/{project.name}@sha256:" + "a" * 64,
            "findings": list(project.findings),
        }],
        "unscanned": [],
    })


def _write_backups(paths: BoxPaths, project: FixtureProject, now: datetime) -> None:
    backups = paths.project_backups(project.name)
    backups.mkdir(parents=True)
    for kind, hours in project.backups:
        taken = now - timedelta(hours=hours)
        path = backups / f"{project.name}-{taken:%Y-%m-%dT%H%M%S}-{kind}.tar.gz.age"
        path.write_bytes(b"\0" * 4096)
        os.utime(path, (taken.timestamp(), taken.timestamp()))


def _write_dev_data(paths: BoxPaths, project: FixtureProject, now: datetime) -> None:
    dev = paths.root / DEV_DIR
    status, message = project.smoke
    write_json(dev / "checks" / f"{project.name}.json", {
        "project": project.name, "exit_code": _EXIT_CODES[status], "status": status,
        "smoke": {"status": status, "message": message},
    })
    for svc in project.services:
        lines = [
            f"{project.name}-{svc}-1  | {iso(now - timedelta(minutes=30 - i))} "
            f"GET /{'health' if i % 3 else 'api/items'} 200 {12 + i}ms"
            for i in range(30)
        ]
        log = dev / "logs" / project.name / f"{svc}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("".join(f"{line}\n" for line in lines))
