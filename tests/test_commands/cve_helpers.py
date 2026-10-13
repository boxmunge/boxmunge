# SPDX-License-Identifier: Apache-2.0
"""Shared builders for the CVE scan / enforcement / resume command tests.

These drive the real scan, quarantine and alerting code. Only the Docker
and Trivy primitives (container digests, image scans, Caddy reload,
compose stop/up) are stubbed by the individual tests.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

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


def finding(
    cve: str = "CVE-2026-0001", *, sev: Severity = Severity.CRITICAL,
    pkg: str = "openssl", fix: str | None = None,
) -> Finding:
    """A distro-acknowledged, network-reachable finding (quarantines ≥ High)."""
    return Finding(
        cve_id=cve, severity=sev, package=pkg, installed_version="1",
        fixed_version=fix, title="", primary_url=None,
        attack_vector=AttackVector.NETWORK, status=VulnStatus.AFFECTED,
        vendor_severities={"debian": sev}, pkg_class=PkgClass.OS,
    )


CRIT = finding()


def scan_result(ref: str, findings=()) -> ScanResult:
    return ScanResult(ref, tuple(findings), datetime.now(timezone.utc), None)


def write_project(
    paths: BoxPaths, name: str, *, services=("web",), images=None,
    security: dict | None = None,
) -> None:
    """Write manifest + compose for ``name``.

    ``images`` maps service → compose image; a service missing from it is
    build-only. Default: every service declares ``<name>-<svc>:1``.
    """
    images = images if images is not None else {s: f"{name}-{s}:1" for s in services}
    proj = paths.projects / name
    proj.mkdir(parents=True)
    manifest = {
        "schema_version": 2, "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ", "source": "bundle",
        "project": name, "hosts": [f"{name}.example.com"],
        "services": {s: {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"}
                     for s in services},
    }
    if security is not None:
        manifest["security"] = security
    (proj / "manifest.yml").write_text(yaml.safe_dump(manifest))
    compose_services = {
        s: ({"image": images[s]} if s in images else {"build": "."}) for s in services
    }
    (proj / "compose.yml").write_text(yaml.safe_dump({"services": compose_services}))


def make_box(tmp_path, projects=("demo",), **project_kwargs) -> BoxPaths:
    """A box with registered projects and the migration grace already over."""
    paths = BoxPaths(root=tmp_path)
    for d in (paths.state, paths.deploy_state, paths.caddy_sites, paths.config):
        d.mkdir(parents=True, exist_ok=True)
    for name in projects:
        write_project(paths, name, **project_kwargs)
    (paths.state / "projects.txt").write_text("".join(f"{n}\n" for n in projects))
    expired = datetime(2025, 1, 1, tzinfo=timezone.utc)
    paths.cve_grace_state.write_text(json.dumps({
        "installed_at": expired.isoformat(),
        "expires_at": (expired + timedelta(hours=24)).isoformat(),
        "heads_up_sent": True,
    }))
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
            "boxmunge.cve.alerting.send_notification", self._send,
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
        for name in ("caddy_reload", "compose_stop", "compose_up"):
            monkeypatch.setattr(f"boxmunge.cve.quarantine.{name}", self._recorder(name))
        monkeypatch.setattr("boxmunge.cve.quarantine.project_restart_policies",
                            lambda project: {n: p for n, p in self.policies.items()
                                             if n.startswith(f"{project}-")})
        monkeypatch.setattr("boxmunge.cve.quarantine.set_restart_policy", self._set_policy)

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
