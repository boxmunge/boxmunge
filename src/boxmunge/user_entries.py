# SPDX-License-Identifier: Apache-2.0
"""Manifest entries that only say who a compose-only service runs as.

`services.<svc>: {security: {user: ..., reason: ...}}`, with no port,
routes or `internal: true`, declares the user of a service compose.yml
alone defines, and nothing else: the service keeps every other behaviour
of a compose-only service (no read-only root filesystem, no env files, no
proxy network). Loading a manifest moves these entries out of `services`
into USER_ENTRIES, so everything that treats `services` as the manifest's
own services (the overlay, Caddy, smoke, health, the views) never sees
them; run_as reads them from there.
"""
from __future__ import annotations

from typing import Any

USER_ENTRIES = "user_entries"  # set by loading; never written in manifest.yml
_ALLOWED = frozenset({"user", "reason"})


def is_user_entry(svc: Any) -> bool:
    """An entry with none of what makes a manifest service its own."""
    return (isinstance(svc, dict) and "port" not in svc and "routes" not in svc
            and svc.get("internal") is not True)


def user_entry_problems(name: str, svc: dict[str, Any]) -> list[str]:
    """What is wrong with a user entry (validated as written)."""
    hint = (f"An entry for service '{name}' with no port, routes or internal: true only "
            f"says who a compose-only service runs as")
    extra = sorted(set(svc) - {"security"})
    if extra:
        return [f"{hint}, so it may hold only security: {{user, reason}}; it also has "
                f"{', '.join(extra)}. Remove them, or declare the service fully "
                f"(internal: true, or a port and routes)."]
    sec = svc.get("security")
    if not isinstance(sec, dict) or "user" not in sec:
        return [f"{hint}: give it security.user (root, image or \"<uid>:<gid>\"), or "
                f"declare the service fully (internal: true, or a port and routes)."]
    extra = sorted(set(sec) - _ALLOWED)
    if extra:
        return [f"{hint}, so its security block may hold only user and reason; it also "
                f"has {', '.join(extra)}. Declare the service fully (internal: true) to "
                f"set those."]
    return []


def split_user_entries(manifest: dict[str, Any]) -> dict[str, Any]:
    """The manifest with user entries moved out of `services`."""
    services = manifest.get("services")
    if not isinstance(services, dict):
        return manifest
    entries = {n: s for n, s in services.items() if is_user_entry(s)}
    if not entries:
        return manifest
    return {**manifest, "services": {n: s for n, s in services.items() if n not in entries},
            USER_ENTRIES: entries}


def service_entry(manifest: dict[str, Any], service: str) -> dict[str, Any] | None:
    """A service's manifest entry, full or user-only."""
    for key in ("services", USER_ENTRIES):
        entries = manifest.get(key)
        if isinstance(entries, dict) and isinstance(entries.get(service), dict):
            return entries[service]
    return None


def entries_missing_from(user_entries: dict[str, Any] | None,
                         compose_services: dict[str, Any]) -> list[str]:
    return [f"manifest.yml declares who service '{n}' runs as, but compose.yml does not "
            f"define it. Fix the name, or remove the entry."
            for n in sorted(user_entries or {}) if n not in compose_services]
