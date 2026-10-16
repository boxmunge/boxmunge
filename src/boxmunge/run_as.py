# SPDX-License-Identifier: Apache-2.0
"""Which user each service runs as.

`security.user` (project level, overridden per service) is `root`, `image`
or "<uid>:<gid>" with both ids in 1..65535; `root` and `image` need the
block's `reason`, as other opt-outs do. A compose `user:` is the operator's
explicit choice and wins; its numeric parts must be mappable (0..65535).
"""
from __future__ import annotations

import re
from typing import Any

from boxmunge.security_overlay import SecurityValidationError

USER_ROOT = "root"
USER_IMAGE = "image"
MAX_ID = 65535
_NUMERIC = re.compile(r"([0-9]+):([0-9]+)")


def validate_user_field(block: dict[str, Any], context: str) -> None:
    """Check a security block's `user`. Raises SecurityValidationError."""
    if "user" not in block:
        return
    value = block["user"]
    if isinstance(value, bool) or not isinstance(value, str):
        raise SecurityValidationError(
            f"{context}: security.user must be a string: root, image, or a quoted "
            f"\"<uid>:<gid>\" (unquoted, YAML may read it as a number), got {value!r}")
    if value in (USER_ROOT, USER_IMAGE):
        reason = block.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            who = "root" if value == USER_ROOT else "the image's own user, which may be root"
            raise SecurityValidationError(
                f"{context}: security.user: {value} runs the service as {who}, so it "
                f"needs a non-empty reason in the same security block")
        return
    match = _NUMERIC.fullmatch(value)
    if match is None or not all(1 <= int(g) <= MAX_ID for g in match.groups()):
        raise SecurityValidationError(
            f"{context}: security.user {value!r} must be root, image, or \"<uid>:<gid>\" "
            f"with each id between 1 and {MAX_ID} (a gid of 0 only through root or image)")


def declared_user(project_security: dict[str, Any] | None,
                  manifest_service: dict[str, Any] | None) -> tuple[str | None, str | None]:
    """(security.user, its block's reason): the service's own, else the project's."""
    svc_sec = (manifest_service or {}).get("security") if isinstance(manifest_service, dict) else None
    for block in (svc_sec, project_security):
        if isinstance(block, dict) and "user" in block:
            return block["user"], block.get("reason")
    return None, None


def compose_user_text(raw: Any) -> str | None:
    """A compose `user:` as Docker reads it (YAML may give an int), or None."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return str(raw)
    return raw if isinstance(raw, str) and raw.strip() else None


def compose_user_problems(services: dict[str, Any],
                          manifest_services: dict[str, Any] | None) -> list[str]:
    """Unmappable compose `user:` ids, and a compose `user:` on a service whose
    own manifest security block also sets `user`."""
    problems = []
    for name, svc in services.items():
        if not isinstance(svc, dict) or "user" not in svc:
            continue
        text = compose_user_text(svc["user"])
        if text is None:
            problems.append(f"service {name}: user = {svc['user']!r} must be a uid, a "
                            f"name, or uid:gid")
            continue
        for part in text.split(":", 1):
            if part.isdigit() and int(part) > MAX_ID:
                problems.append(f"service {name}: user = {text!r}: id {part} is above "
                                f"{MAX_ID}, which a remapped daemon cannot map")
        own = (manifest_services or {}).get(name)
        own_sec = own.get("security") if isinstance(own, dict) else None
        if isinstance(own_sec, dict) and "user" in own_sec:
            problems.append(f"service {name}: compose.yml sets user: {text!r} and the "
                            f"manifest sets security.user: {own_sec['user']!r}; keep one")
    return problems
