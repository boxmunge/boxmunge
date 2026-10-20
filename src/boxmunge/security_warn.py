# SPDX-License-Identifier: Apache-2.0
"""Deploy-time SECURITY OFF warning emitter.

Lives outside boxmunge.security_overlay (which is a pure module — no I/O).
Called from deploy/stage/promote command paths.
"""
from __future__ import annotations

from typing import Any

from boxmunge.log import log_operation, log_warning
from boxmunge.published_ports import declared_ports, describe, is_widened
from boxmunge.security_overlay import services_with_off_profile, format_off_warning


def undeclared_services(manifest: dict[str, Any], user_compose: Any) -> list[str]:
    """Return compose services the manifest does not declare, in compose order."""
    declared = manifest.get("services") or {}
    services = user_compose.get("services") if isinstance(user_compose, dict) else None
    return [name for name in (services or {}) if name not in declared]


def undeclared_service_warning(project: str, svc_name: str) -> str:
    """The deploy/stage/validate warning for one undeclared compose service."""
    return (
        f"[WARNING] {project}/{svc_name} is in compose.yml but not declared in "
        f"manifest.yml, so it runs WITHOUT a read-only root filesystem (it still "
        f"gets no-new-privileges, init, the process limit and the capability "
        f"drops). To make its root filesystem read-only, declare it in "
        f"manifest.yml under services: with `internal: true` (no port or routes "
        f"needed) and a `writable:` block: `ephemeral:` for the paths it writes "
        f"if it keeps no data in compose.yml volumes, or `external: true` to keep "
        f"its compose.yml volumes and add the paths it writes as compose `tmpfs:` "
        f"entries (PostgreSQL needs /tmp and /var/run/postgresql). "
        f"Without `read_only: true` in compose.yml it also adds +1 to the CVE "
        f"severity of every finding in the whole project: in 0.11.0 that only "
        f"warns (`boxmunge security {project}`), and from 0.12 it quarantines. "
        f"A future boxmunge release will make a read-only root filesystem the "
        f"default for undeclared services too."
    )


def warn_off_services(paths: Any, manifest: dict[str, Any], component: str) -> None:
    """Emit a SECURITY OFF warning to stdout and the operational log.

    Called by deploy/stage/promote after the compose overlay write.
    Repeated by design — see TRUST_MODEL.md "Per-Project Container Hardening".
    """
    off = services_with_off_profile(manifest)
    if not off:
        return
    project = manifest["project"]
    print(format_off_warning(project, off))
    for svc_name, reason in off:
        log_warning(
            component,
            f"SECURITY OFF: {project}/{svc_name} (reason: {reason})",
            paths,
            project=project,
            detail={
                "event": "security_off",
                "service": svc_name,
                "reason": reason,
            },
        )


def warn_writable_state(
    paths: Any,
    manifest: dict[str, Any],
    user_compose: dict[str, Any] | None,
    component: str,
) -> None:
    """v0.9: emit deploy-time visibility for writable surface choices.

    Two distinct signals, both fired on every deploy:

      [WARNING]  for any service whose user compose declares
                 `read_only: false`. v0.8 silently honoured this override
                 via compose-merge semantics — v0.9 surfaces it. CVE
                 hardening penalty still attaches.

      [INFO]     for any service whose manifest declares
                 `writable.external: true`. boxmunge is delegating the
                 writable surface to compose.yml for this service —
                 operators see a reminder every deploy.

    Shape mirrors warn_off_services: stdout + structured log entry per
    affected service, repeated by design.
    """
    project = manifest.get("project", "<unknown>")
    services = manifest.get("services", {}) or {}
    user_services: dict[str, Any] = {}
    if isinstance(user_compose, dict):
        raw = user_compose.get("services") or {}
        if isinstance(raw, dict):
            user_services = raw

    # 0. Services only in compose.yml run without a read-only rootfs.
    for svc_name in undeclared_services(manifest, user_compose):
        print(undeclared_service_warning(project, svc_name))
        log_warning(
            component, f"undeclared service, no read-only rootfs: {project}/{svc_name}",
            paths, project=project,
            detail={"event": "undeclared_service", "service": svc_name},
        )

    # 1. read_only: false in user compose — per-service warning.
    for svc_name in services:
        user_svc = user_services.get(svc_name)
        if not isinstance(user_svc, dict):
            continue
        # bool is a subtype of int — check explicitly for False to avoid
        # accidentally matching `read_only: 0`.
        if user_svc.get("read_only") is False:
            print(
                f"[WARNING] {project}/{svc_name} declares "
                f"`read_only: false` in compose.yml, opting out of the "
                f"read-only rootfs default. CVE hardening penalty "
                f"applies. If your app needs specific writable paths "
                f"under a read-only rootfs, prefer "
                f"`services.{svc_name}.writable` in manifest.yml instead."
            )
            log_warning(
                component,
                f"read_only:false: {project}/{svc_name}",
                paths,
                project=project,
                detail={
                    "event": "read_only_false",
                    "service": svc_name,
                },
            )

    # 2. writable.external: true in manifest — per-service info.
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        writable_block = svc.get("writable")
        if not isinstance(writable_block, dict):
            continue
        if writable_block.get("external") is True:
            print(
                f"[INFO] {project}/{svc_name} uses externally-managed "
                f"writability (writable.external: true). boxmunge "
                f"defers all tmpfs and volume declarations to "
                f"compose.yml for this service."
            )
            log_operation(
                component,
                f"writable external: {project}/{svc_name}",
                paths,
                project=project,
                detail={
                    "event": "writable_external",
                    "service": svc_name,
                },
            )


def warn_published_ports(paths: Any, manifest: dict[str, Any], component: str) -> None:
    """Emit a [WARNING] for every opt-in published port, on every deploy.

    Published ports bypass Caddy, UFW and CrowdSec; a widened one (any
    host_ip other than loopback) is reachable from the network.
    """
    project = manifest.get("project", "<unknown>")
    for entry in declared_ports(manifest.get("security")):
        reach = (
            "REACHABLE FROM THE NETWORK, bypassing UFW and CrowdSec"
            if is_widened(entry) else "reachable from this host only"
        )
        print(
            f"[WARNING] {project} publishes {describe(entry)} outside Caddy, "
            f"{reach}. Reason recorded in manifest: {entry['reason']!r}"
        )
        log_warning(
            component, f"published port {describe(entry)}: {project}",
            paths, project=project,
            detail={"event": "published_port", "port": describe(entry),
                    "widened": is_widened(entry), "reason": entry["reason"]},
        )
