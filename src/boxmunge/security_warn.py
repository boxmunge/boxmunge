# SPDX-License-Identifier: Apache-2.0
"""Deploy-time SECURITY OFF warning emitter.

Lives outside boxmunge.security_overlay (which is a pure module — no I/O).
Called from deploy/stage/promote command paths.
"""
from __future__ import annotations

from typing import Any

from boxmunge.log import log_warning
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
        )
