# SPDX-License-Identifier: Apache-2.0
"""Shared builders for the CVE scan / enforcement / resume command tests.

These drive the real scan, quarantine and alerting code. Only the Docker
and Trivy primitives (container digests, image scans, Caddy reload,
compose stop/up) are stubbed by the individual tests.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import yaml

from boxmunge.cve.scanner import (
    AttackVector,
    Finding,
    PkgClass,
    ScanResult,
    Severity,
    VulnStatus,
)
from boxmunge.docker import DockerError
from boxmunge.paths import BoxPaths
from tests.deploy_helpers import mark_deployed


def finding(
    cve: str = "CVE-2026-0001", *, sev: Severity = Severity.CRITICAL,
    pkg: str = "openssl", fix: str | None = None,
) -> Finding:
    """A distro-acknowledged, network-reachable finding (quarantines ≥ Medium
    under strict; under balanced only a KEV listing quarantines)."""
    return Finding(
        cve_id=cve, severity=sev, package=pkg, installed_version="1",
        fixed_version=fix, title="", primary_url=None,
        attack_vector=AttackVector.NETWORK, status=VulnStatus.AFFECTED,
        vendor_severities={"debian": sev}, pkg_class=PkgClass.OS,
    )


CRIT = finding()

# Strict: a non-KEV finding ≥ Medium quarantines. Balanced quarantines only
# on CISA KEV; tests of balanced pass {"posture": "balanced"}.
STRICT = {"posture": "strict"}


def fresh_kev(monkeypatch, *cves: str):
    """A fresh KEV catalog listing ``cves`` for `security resume`, which
    refuses a lift no usable catalog backs (cve.lift_rule)."""
    from boxmunge.cve.kev import KevCatalog
    now = datetime.now(timezone.utc)
    kev = KevCatalog(frozenset(cves), now, now, "https://kev.example/feed.json")
    monkeypatch.setattr("boxmunge.commands.security_resume.load_kev", lambda paths: kev)
    return kev


def scan_result(ref: str, findings=()) -> ScanResult:
    return ScanResult(ref, tuple(findings), datetime.now(timezone.utc), None)


def write_project(
    paths: BoxPaths, name: str, *, services=("web",), images=None,
    security: dict | None = None,
) -> None:
    """Write manifest + compose for ``name``.

    ``images`` maps service → compose image; a service missing from it is
    build-only. Default: every service declares ``<name>-<svc>:1``.

    ``security`` defaults to STRICT: these tests drive the quarantine
    machinery with plain (non-KEV) findings, which balanced only alerts on.
    Strict requires a read-only root, so each service declares one.
    """
    if security is None:
        security = STRICT
    images = images if images is not None else {s: f"{name}-{s}:1" for s in services}
    proj = paths.projects / name
    proj.mkdir(parents=True)
    manifest = {
        "schema_version": 2, "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ", "source": "bundle",
        "project": name, "hosts": [f"{name}.example.com"],
        "services": {s: {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"}
                     for s in services},
    }
    manifest["security"] = security
    (proj / "manifest.yml").write_text(yaml.safe_dump(manifest))
    compose_services = {
        s: {**({"image": images[s]} if s in images else {"build": "."}), "read_only": True}
        for s in services
    }
    (proj / "compose.yml").write_text(yaml.safe_dump({"services": compose_services}))
    mark_deployed(paths, name)


def make_box(tmp_path, projects=("demo",), **project_kwargs) -> BoxPaths:
    """A box with registered projects."""
    paths = BoxPaths(root=tmp_path)
    for d in (paths.state, paths.deploy_state, paths.caddy_sites, paths.config):
        d.mkdir(parents=True, exist_ok=True)
    for name in projects:
        write_project(paths, name, **project_kwargs)
    (paths.state / "projects.txt").write_text("".join(f"{n}\n" for n in projects))
    return paths


class Pushover:
    """Capture every Pushover send made through the real alerting path."""

    def __init__(self, monkeypatch, paths: BoxPaths) -> None:
        self.sent: list[tuple[str, str, int]] = []
        paths.config_file.write_text(yaml.safe_dump({
            "hostname": "box.example.com", "admin_email": "ops@example.com",
            "pushover": {"user_key": "u", "app_token": "t"},
        }))
        monkeypatch.setattr(
            "boxmunge.notify.send_notification", self._send,
        )

    def _send(self, user_key, app_token, title, body, priority=0) -> bool:
        self.sent.append((title, body, priority))
        return True

    def titles(self) -> list[str]:
        return [t for t, _, _ in self.sent]

    def clear(self) -> None:
        self.sent.clear()


def seed_quarantine(paths: BoxPaths, name: str = "demo", **extra) -> None:
    paths.project_quarantine_state(name).write_text(json.dumps({
        "quarantined_at": "2026-10-01T03:00:00+00:00", "cve_id": "CVE-2026-0001",
        "severity": "Critical", "effective_severity": "Critical",
        "explanation": "test", "image_ref": f"{name}-web:1",
        "action_complete": True, **extra,
    }))


BALANCED = {"posture": "balanced", "dangerously_disable_quarantine": False, "runtimes": None}


def make_clearance(project: str = "demo", images=None, *, before=None, after=BALANCED,
                   at_risk=()):
    """A production release's clearance; `before` None is a quarantine whose
    record does not keep the policy."""
    from boxmunge.commands.quarantine_gate import Clearance
    from boxmunge.commands.security_scan_inputs import ProjectHardening
    from boxmunge.cve.hardening import HardeningProfile
    return Clearance(project, project, "CVE-2026-0001", images or {},
                     ProjectHardening(HardeningProfile(True, True, False, False), None),
                     after, before, tuple(at_risk))


class Docker:
    """Records the Docker primitives the quarantine action calls.

    ``fail`` maps a primitive name to how many upcoming calls should raise.
    """

    def __init__(self, monkeypatch) -> None:
        self.calls: list[str] = []
        self.kwargs: dict[str, dict] = {}
        self.fail: dict[str, int] = {}
        # Restart policy of each project container, as `docker update` sets it.
        self.policies: dict[str, str] = {}
        for name in ("caddy_reload", "compose_stop"):
            monkeypatch.setattr(f"boxmunge.cve.quarantine.{name}", self._recorder(name))
        monkeypatch.setattr("boxmunge.compose_guard.compose_up", self._recorder("compose_up"))
        # The smoke test a lift runs is a `docker exec`.
        self.smoke: tuple[bool, str] = (True, "ok")
        monkeypatch.setattr("boxmunge.commands.quarantine_lift.run_smoke",
                            lambda project, paths: self.smoke)
        monkeypatch.setattr("boxmunge.restart_hold.project_restart_policies",
                            lambda *, project_name: {
                                n: p for n, p in self.policies.items()
                                if n.startswith(f"{project_name}-")})
        monkeypatch.setattr("boxmunge.restart_hold.set_restart_policy", self._set_policy)

    def _set_policy(self, names, policy) -> None:
        for name in names:
            self.policies[name] = policy

    def _recorder(self, name: str):
        def call(*args, **kwargs):
            self.calls.append(name)
            self.kwargs[name] = kwargs
            if self.fail.get(name, 0) > 0:
                self.fail[name] -= 1
                raise DockerError(f"{name} timed out")
        return call


def render_site(paths: BoxPaths, manifest: dict) -> str:
    """Stand-in for caddy.prepare_caddy_config: writes the project's site
    and returns its text."""
    site = paths.project_caddy_site(manifest["project"])
    site.parent.mkdir(parents=True, exist_ok=True)
    content = f"{manifest['project']}.example.com {{}}\n"
    site.write_text(content)
    return content


def scan_and_send(paths, project, **kwargs):
    """scan_one_project, then deliver every collected alert at once: what a
    single-project `security scan <p>` does."""
    from boxmunge.commands.security_scan_core import scan_one_project
    from boxmunge.cve.alerting import send_alerts
    collected: list = []
    try:
        return scan_one_project(paths, project, alerts=collected, **kwargs)
    finally:
        send_alerts(tuple(collected), paths)
