# SPDX-License-Identifier: Apache-2.0
"""Each service's hardening fragment in the generated compose overlay.

Split from boxmunge.compose: the overlay's per-service security keys, and
the rule that a user's own `read_only` or `/tmp` declaration wins.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from boxmunge.security_overlay import render_compose_security_fragment, resolve_security

if TYPE_CHECKING:
    from boxmunge.run_as import ServiceUser


# ---------------------------------------------------------------------------
# v0.8: user-wins-on-explicit-declarations for read_only / tmpfs.
#
# Compose's merge keeps the later file's scalar (the overlay would overwrite
# a deliberate `read_only: false`) and concatenates lists (a user
# `tmpfs: ['/tmp:size=128m']` would clash with the overlay's `/tmp`). So the
# overlay omits either field when the user already declared it for that
# service, rather than rejecting the declaration.
# ---------------------------------------------------------------------------


def _user_declared_read_only(svc: dict[str, Any]) -> bool:
    """True iff the user compose declares `read_only` on this service.

    Any value counts (True or False) — the point is "the user has
    expressed intent", not "the user agrees with the overlay".
    """
    return "read_only" in svc


def _volume_target(entry: Any) -> str | None:
    """Extract the container target path from a compose volume entry.

    Short syntax: 'src:target[:opts]' — if it has a colon, the second
    field is the target. Anonymous volume short syntax ('/path' with
    no colon) is itself the target.
    Long syntax: {target: '/path', ...}.
    """
    if isinstance(entry, str):
        if ":" not in entry:
            # Anonymous volume — the whole string is the target.
            return entry
        parts = entry.split(":")
        if len(parts) >= 2:
            return parts[1]
        return None
    if isinstance(entry, dict):
        target = entry.get("target")
        return target if isinstance(target, str) else None
    return None


def _tmpfs_target(entry: Any) -> str | None:
    """Extract the target path from a compose tmpfs entry.

    Short syntax: '/tmp' or '/tmp:size=64m' — target is everything before
    the first colon.
    """
    if not isinstance(entry, str):
        return None
    if ":" in entry:
        return entry.split(":", 1)[0]
    return entry


def _user_claims_tmp(svc: dict[str, Any]) -> bool:
    """True iff the user compose has any /tmp claim on this service.

    Conservative detection over both `tmpfs` (string list) and `volumes`
    (short or long syntax). A weird combo that slips through would
    surface as a Compose-up time error, which is acceptable.
    """
    tmpfs = svc.get("tmpfs")
    if isinstance(tmpfs, list):
        for entry in tmpfs:
            if _tmpfs_target(entry) == "/tmp":
                return True
    volumes = svc.get("volumes")
    if isinstance(volumes, list):
        for entry in volumes:
            if _volume_target(entry) == "/tmp":
                return True
    return False


def hardening_fragment(
    project_security: dict[str, Any] | None,
    service_security: dict[str, Any] | None,
    user_svc: Any,
) -> dict[str, Any]:
    """Render one service's hardening fragment for its effective profile.

    v0.8 user-wins rule: when compose.yml already declares `read_only` or
    claims `/tmp` for this service, the overlay omits its own value. See
    the module-level comment above `_user_declared_read_only` for why we
    omit instead of reject for these two fields.
    """
    resolved = resolve_security(project_security, service_security)
    fragment = render_compose_security_fragment(resolved)
    if isinstance(user_svc, dict):
        if "read_only" in fragment and _user_declared_read_only(user_svc):
            fragment.pop("read_only")
        if "tmpfs" in fragment and _user_claims_tmp(user_svc):
            fragment.pop("tmpfs")
    return fragment


def tmpfs_for(entry: str, ids: tuple[int, int]) -> str:
    """A tmpfs entry a numeric non-root user can write. A tmpfs over an image
    path inherits that directory's mode, so the mode is set explicitly."""
    if ":" in entry:
        return entry  # options the operator chose
    if entry == "/tmp":
        return "/tmp:mode=1777"
    return f"{entry}:uid={ids[0]},gid={ids[1]},mode=0700"


def apply_run_user(fragment: dict[str, Any], user: ServiceUser | None) -> dict[str, Any]:
    """Add the recorded user to a service fragment and give its tmpfs mounts
    to a numeric non-root user. No record (a project deployed before users
    were decided) leaves the fragment as it was."""
    value = user.emitted() if user is not None else None
    if value is None:
        return fragment
    fragment["user"] = value
    ids = user.nonroot_ids()
    if ids and isinstance(fragment.get("tmpfs"), list):
        fragment["tmpfs"] = [tmpfs_for(e, ids) for e in fragment["tmpfs"]]
    return fragment
