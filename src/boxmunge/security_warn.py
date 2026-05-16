# SPDX-License-Identifier: Apache-2.0
"""Deploy-time SECURITY OFF warning emitter.

Lives outside boxmunge.security_overlay (which is a pure module — no I/O).
Called from deploy/stage/promote command paths.
"""
from __future__ import annotations

from typing import Any

from boxmunge.log import log_operation, log_warning
from boxmunge.security_overlay import services_with_off_profile, format_off_warning


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
