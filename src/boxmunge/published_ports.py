# SPDX-License-Identifier: Apache-2.0
"""Opt-in host-published ports: the manifest's `security.published_ports`.

All ingress is meant to go through Caddy. A `ports:` entry in compose.yml
publishes straight onto the host, and Docker installs its own iptables
rules for it, so the port bypasses UFW and the CrowdSec bouncer. The
compose validator therefore refuses `ports:` outright, and a port that
truly must be published is declared here instead, with a reason. The
overlay generator publishes it, bound to 127.0.0.1 (reachable only from
the host, for example through an SSH tunnel) unless the entry explicitly
widens `host_ip`.

Pure module: no I/O. Validation returns problem strings; the caller
attaches its own context and exception type.
"""
from __future__ import annotations

import ipaddress
from typing import Any

LOOPBACK = "127.0.0.1"
_PROTOCOLS = frozenset({"tcp", "udp"})
_KEYS = frozenset({"service", "port", "host_port", "host_ip", "protocol", "reason"})
_EXAMPLE = (
    "e.g. {service: db, port: 5432, reason: \"admin access over an SSH tunnel\"}"
)


def _port_ok(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535


def _entry_problems(i: int, entry: Any) -> list[str]:
    where = f"published_ports[{i}]"
    if not isinstance(entry, dict):
        return [f"{where} must be a mapping, {_EXAMPLE}"]
    problems = []
    unknown = set(entry) - _KEYS
    if unknown:
        problems.append(f"{where} has unknown key(s) {sorted(unknown)}; allowed: {sorted(_KEYS)}")
    if not isinstance(entry.get("service"), str) or not entry.get("service"):
        problems.append(f"{where} needs 'service': the compose service to publish")
    if not _port_ok(entry.get("port")):
        problems.append(f"{where} needs 'port': the container port, an integer 1-65535")
    if "host_port" in entry and not _port_ok(entry["host_port"]):
        problems.append(f"{where} host_port must be an integer 1-65535")
    if "protocol" in entry and entry["protocol"] not in _PROTOCOLS:
        problems.append(f"{where} protocol must be one of {sorted(_PROTOCOLS)}")
    if "host_ip" in entry:
        try:
            ipaddress.ip_address(entry["host_ip"])
        except (TypeError, ValueError):
            problems.append(f"{where} host_ip must be an IP address, got {entry['host_ip']!r}")
    reason = entry.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        problems.append(
            f"{where} needs a non-empty 'reason': published ports bypass Caddy, "
            f"UFW and CrowdSec, so say why this one is needed"
        )
    return problems


def published_ports_problems(value: Any) -> list[str]:
    """Return every problem with a `security.published_ports` value."""
    if not isinstance(value, list) or not value:
        return [f"published_ports must be a non-empty list, {_EXAMPLE}"]
    problems: list[str] = []
    for i, entry in enumerate(value):
        problems.extend(_entry_problems(i, entry))
    if problems:
        return problems
    seen: set[tuple[str, int, str]] = set()
    for entry in value:
        key = (_host_ip(entry), _host_port(entry), _protocol(entry))
        if key in seen:
            problems.append(f"published_ports publishes {key[0]}:{key[1]}/{key[2]} twice")
        seen.add(key)
    return problems


def _host_ip(entry: dict[str, Any]) -> str:
    return entry.get("host_ip", LOOPBACK)


def _host_port(entry: dict[str, Any]) -> int:
    return entry.get("host_port", entry["port"])


def _protocol(entry: dict[str, Any]) -> str:
    return entry.get("protocol", "tcp")


def is_widened(entry: dict[str, Any]) -> bool:
    """True if the entry is reachable from beyond the host itself."""
    return not ipaddress.ip_address(_host_ip(entry)).is_loopback


def declared_ports(project_security: Any) -> list[dict[str, Any]]:
    """Return the validated `published_ports` entries of a security block."""
    if not isinstance(project_security, dict):
        return []
    return list(project_security.get("published_ports") or [])


def overlay_ports(project_security: Any) -> dict[str, list[dict[str, Any]]]:
    """Return {service: [compose long-syntax port]} for the overlay."""
    out: dict[str, list[dict[str, Any]]] = {}
    for entry in declared_ports(project_security):
        out.setdefault(entry["service"], []).append({
            "target": entry["port"],
            "published": str(_host_port(entry)),
            "host_ip": _host_ip(entry),
            "protocol": _protocol(entry),
        })
    return out


def describe(entry: dict[str, Any]) -> str:
    """One-line description, e.g. `127.0.0.1:5432 -> db:5432/tcp`."""
    return (
        f"{_host_ip(entry)}:{_host_port(entry)} -> "
        f"{entry['service']}:{entry['port']}/{_protocol(entry)}"
    )
