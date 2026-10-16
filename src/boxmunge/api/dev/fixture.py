# SPDX-License-Identifier: Apache-2.0
"""Write and recognise the dev fixture box.

`boxmunge-apid --make-fixture DIR` writes a realistic box into DIR: five
projects in different lifecycle states (running, paused, CVE-quarantined,
failing with a staged release, pre-registered), scan findings, backups, inbox
bundles, an operational log, a health report and finished jobs with events.

Dev mode serves only a directory carrying FIXTURE_MARKER, so it can never be
pointed at a real box by mistake.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from boxmunge.api.dev.fixture_projects import (
    DEV_DIR, PROJECTS, QUARANTINE_CVE, iso, write_json, write_project,
)
from boxmunge.paths import BoxPaths
from boxmunge.ulid import generate_ulid

FIXTURE_MARKER = ".boxmunge-fixture"
FIXTURE_HOSTNAME = "box.example.test"

_HEALTH_CHECKS = (
    ("docker", "ok", "Docker daemon running"),
    ("caddy", "ok", "Caddy container healthy"),
    ("system-container", "ok", "boxmunge-system running"),
    ("permissions", "ok", "Critical file permissions correct"),
    ("age-key", "ok", "Backup key valid"),
    ("project-containers", "ok",
     "All 2 checked project(s) have running containers (2 blocked — see `lifecycle`)"),
    ("lifecycle", "warn", f"quarantined: billing ({QUARANTINE_CVE}); paused: blog"),
    ("config-drift", "ok", "All generated configs match"),
    ("recent-errors", "ok", "2 error(s) in last 24h (within threshold)"),
    ("ufw", "ok", "Firewall active"),
    ("crowdsec", "ok", "CrowdSec running"),
    ("auto-updates", "ok", "Unattended security upgrades enabled"),
    ("timers", "ok", "All boxmunge timers active"),
)

# (hours ago, level, component, project, message, detail)
_OPLOG = (
    (75, "info", "deploy", "shop", "Deployed", {"source": "bundle"}),
    (34, "info", "deploy", "wiki", "Deployed", {"source": "bundle"}),
    (26, "info", "pause", "blog", "Paused", {"reason": "Content freeze"}),
    (20, "info", "deploy", "billing", "Deployed", {"source": "bundle"}),
    (10, "info", "deploy", "wiki", "Deployed", {"source": "bundle"}),
    (8, "error", "backup", "wiki", "Backup failed", {"exit_code": 1}),
    (6, "info", "backup", None, "Nightly backups complete", None),
    (5, "warn", "cve", "billing", f"Quarantined: {QUARANTINE_CVE} (Critical)",
     {"cve_id": QUARANTINE_CVE}),
    (3, "info", "deploy", "shop", "Deployed", {"source": "bundle"}),
    (1, "info", "stage", "wiki", "Staged", None),
    (0.25, "error", "health", "wiki", "Smoke failing: GET /health returned 503",
     {"consecutive_failures": 3}),
)

# (action, project, principal, hours ago, final state, error, events)
_JOBS = (
    ("project.deploy", "shop", "plugin:webui", 3, "succeeded", None, (
        {"type": "state", "state": "running"},
        {"type": "step", "step": "snapshot", "status": "started"},
        {"type": "step", "step": "snapshot", "status": "succeeded"},
        {"type": "log", "message": "Pulling registry.example.test/shop/web"},
        {"type": "step", "step": "start", "status": "succeeded"},
        {"type": "step", "step": "smoke", "status": "succeeded"},
        {"type": "state", "state": "succeeded"},
    )),
    ("project.backup", "wiki", "operator:ssh", 8, "failed",
     {"code": "failed", "message": "Backup command exited 1: pg_dump: connection refused"}, (
        {"type": "state", "state": "running"},
        {"type": "step", "step": "dump", "status": "started"},
        {"type": "log", "message": "pg_dump: error: connection to server failed"},
        {"type": "step", "step": "dump", "status": "failed", "message": "exit status 1"},
        {"type": "state", "state": "failed"},
    )),
)


class FixtureError(Exception):
    """A fixture box is missing, or writing one would overwrite something."""


def require_fixture(root: Path) -> None:
    """Refuse any directory that is not a fixture box."""
    if not (root / FIXTURE_MARKER).is_file():
        raise FixtureError(
            f"{root} is not a fixture box (it has no {FIXTURE_MARKER} file). Dev mode "
            f"never serves a real box. Make a fixture with: "
            f"boxmunge-apid --make-fixture <dir>")


def make_fixture(root: Path, *, now: datetime | None = None) -> BoxPaths:
    """Write a fixture box into *root*, which must be new or empty."""
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise FixtureError(f"{root} already exists and is not an empty directory; "
                           f"choose a new one")
    now = now or datetime.now(timezone.utc)
    paths = BoxPaths(root)
    for directory in (paths.config, paths.projects, paths.logs, paths.inbox,
                      paths.jobs_queue):
        directory.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(yaml.safe_dump(
        {"hostname": FIXTURE_HOSTNAME, "admin_email": "ops@example.test"}))
    (paths.state / "projects.txt").write_text(
        "".join(f"{p.name}\n" for p in sorted(PROJECTS, key=lambda p: p.name)))
    for project in PROJECTS:
        write_project(paths, project, now)
    write_json(paths.root / DEV_DIR / "health.json", {
        "healthy": False, "exit_code": 1,
        "checks": [{"name": n, "status": s, "detail": d} for n, s, d in _HEALTH_CHECKS],
    })
    _write_inbox(paths, now)
    _write_oplog(paths, now)
    _write_jobs(paths, now)
    (root / FIXTURE_MARKER).write_text(
        "boxmunge dev fixture. boxmunge-apid --dev serves only directories with this file.\n")
    return paths


def _write_inbox(paths: BoxPaths, now: datetime) -> None:
    for name, hours in (("shop", 1), ("wiki", 2)):
        uploaded = now - timedelta(hours=hours)
        bundle = paths.inbox / f"{name}-{uploaded:%Y-%m-%dT%H%M%S%f}.tar.gz"
        bundle.write_bytes(b"\0" * 2048)
        os.utime(bundle, (uploaded.timestamp(), uploaded.timestamp()))


def _write_oplog(paths: BoxPaths, now: datetime) -> None:
    lines = []
    for hours, level, component, project, msg, detail in _OPLOG:
        entry = {
            "ts": (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": level, "component": component, "project": project, "msg": msg,
        }
        if detail is not None:
            entry["detail"] = detail
        lines.append(json.dumps(entry))
    paths.log_file.write_text("".join(f"{line}\n" for line in lines))


def _write_jobs(paths: BoxPaths, now: datetime) -> None:
    for action, project, principal, hours, state, error, events in _JOBS:
        job_id = generate_ulid()
        created = now - timedelta(hours=hours)
        write_json(paths.jobs_dir / f"{job_id}.json", {
            "id": job_id, "action": action, "principal": principal, "project": project,
            "state": state, "created_at": iso(created),
            "started_at": iso(created + timedelta(seconds=5)),
            "finished_at": iso(created + timedelta(seconds=90)), "error": error,
        })
        lines = [
            json.dumps({"seq": seq, "ts": iso(created + timedelta(seconds=5 + 10 * seq)),
                        **event})
            for seq, event in enumerate(events, start=1)
        ]
        (paths.jobs_dir / f"{job_id}.events.jsonl").write_text(
            "".join(f"{line}\n" for line in lines))
