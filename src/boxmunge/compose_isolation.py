# SPDX-License-Identifier: Apache-2.0
"""Cross-project isolation rules for user compose files.

Every project's compose file runs on the same Docker daemon. These rules
keep one project's compose file from reaching another project: it may
declare and join only its own networks (any alias is fine there: a
project-local network cannot collide with another project's), use only
its own named volumes, and
read host files (secrets, configs, build contexts) only from inside its
own directory. It may not publish ports on the host either; a port that
must be published is declared in the manifest (see `published_ports`). The shared `boxmunge-proxy` network is attached by
boxmunge's overlay for routed services; a compose file may not join it
itself.

Unlike the hardening rules, these are not relaxed by `security.profile:
off`: opting a service out of container hardening does not entitle it to
another project's network or data.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from boxmunge.compose_mounts import host_path_forms, outside_roots

PROXY_NETWORK = "boxmunge-proxy"
_ALLOWED_NETWORK_DRIVERS = frozenset({"bridge"})
_ALLOWED_VOLUME_DRIVERS = frozenset({"local"})


def _own_name_problem(kind: str, key: str, decl: dict[str, Any], project: str) -> str | None:
    """Check a top-level network or volume keeps its project-scoped name."""
    if decl.get("external"):
        hint = (
            f"boxmunge attaches routed services to {PROXY_NETWORK} itself; "
            if kind == "network" and (key == PROXY_NETWORK or decl.get("name") == PROXY_NETWORK)
            else ""
        )
        return (
            f"top-level {kind} {key!r} is external, which reaches outside the "
            f"project. {hint}Remove it; compose.yml may only declare the "
            f"project's own {kind}s."
        )
    expected = f"{project}_{key}"
    name = decl.get("name")
    if name is not None and name != expected:
        return (
            f"top-level {kind} {key!r} sets name: {name!r}, which could be "
            f"another project's {kind}. Remove the name: line; Compose names "
            f"it {expected!r}."
        )
    return None


def _check_networks(doc: dict[str, Any], project: str) -> list[str]:
    networks = doc.get("networks") or {}
    if not isinstance(networks, dict):
        return [f"top-level networks must be a mapping, got {type(networks).__name__}"]
    problems: list[str] = []
    for key, decl in networks.items():
        decl = decl or {}
        if not isinstance(decl, dict):
            problems.append(f"top-level network {key!r} must be a mapping")
            continue
        problem = _own_name_problem("network", key, decl, project)
        if problem:
            problems.append(problem)
            continue
        driver = decl.get("driver")
        if driver is not None and driver not in _ALLOWED_NETWORK_DRIVERS:
            problems.append(
                f"top-level network {key!r} uses driver {driver!r}, which can "
                f"attach containers to the host's networks. Remove the driver: "
                f"line (the default bridge driver is used)."
            )
    return problems


def _check_volumes(doc: dict[str, Any], project: str) -> list[str]:
    volumes = doc.get("volumes") or {}
    if not isinstance(volumes, dict):
        return [f"top-level volumes must be a mapping, got {type(volumes).__name__}"]
    problems: list[str] = []
    for key, decl in volumes.items():
        decl = decl or {}
        if not isinstance(decl, dict):
            problems.append(f"top-level volume {key!r} must be a mapping")
            continue
        problem = _own_name_problem("volume", key, decl, project)
        if problem:
            problems.append(problem)
            continue
        driver = decl.get("driver")
        if decl.get("driver_opts") or (
            driver is not None and driver not in _ALLOWED_VOLUME_DRIVERS
        ):
            problems.append(
                f"top-level volume {key!r} sets driver or driver_opts, which "
                f"can bind any host path into the container. Remove them, or "
                f"bind-mount a directory inside the project instead."
            )
    return problems


def _check_file_refs(doc: dict[str, Any], base_dir: Path, roots: tuple[Path, ...]) -> list[str]:
    """Top-level secrets and configs read host files; keep them in the project."""
    problems: list[str] = []
    for section in ("secrets", "configs"):
        entries = doc.get(section) or {}
        if not isinstance(entries, dict):
            continue
        for key, decl in entries.items():
            path = decl.get("file") if isinstance(decl, dict) else None
            if isinstance(path, str) and outside_roots(path, base_dir, roots):
                norm, _ = host_path_forms(path, base_dir)
                problems.append(
                    f"top-level {section} {key!r} reads {norm}, outside the "
                    f"project directory. Keep the file inside the project "
                    f"directory, or use `secrets set` for secret values."
                )
    return problems


def _service_networks(svc: dict[str, Any]) -> dict[str, Any]:
    nets = svc.get("networks") or {}
    if isinstance(nets, list):
        return {name: None for name in nets}
    return nets if isinstance(nets, dict) else {}


def _check_service(
    svc_name: str, svc: dict[str, Any], declared: set[str],
    base_dir: Path, roots: tuple[Path, ...],
) -> list[str]:
    problems: list[str] = []
    # Declared networks are all project-local (_check_networks refuses
    # external ones), so a service joining only those, with any aliases,
    # cannot place a name on a network another project shares.
    for net in _service_networks(svc):
        if net != "default" and net not in declared:
            problems.append(
                f"service {svc_name}: joins network {net!r}, which this "
                f"compose file does not declare, so it may be shared with other "
                f"projects. Use the project's own networks."
            )
    if svc.get("ports"):
        problems.append(
            f"service {svc_name}: ports: publishes on the host directly, "
            f"bypassing Caddy, UFW and CrowdSec. Remove ports: (routed traffic "
            f"reaches the service through Caddy). If a port must be reachable "
            f"from the host, declare it in manifest.yml under "
            f"security.published_ports with a reason; boxmunge then publishes "
            f"it on 127.0.0.1."
        )
    if svc.get("external_links"):
        problems.append(
            f"service {svc_name}: external_links reach containers outside this "
            f"project. Remove them; services in this file can reach each other "
            f"by service name."
        )
    for entry in svc.get("volumes_from") or []:
        if isinstance(entry, str) and entry.strip().lower().startswith("container:"):
            problems.append(
                f"service {svc_name}: volumes_from {entry!r} mounts another "
                f"container's volumes, which may be another project's. Name a "
                f"service in this compose file instead."
            )
    build = svc.get("build")
    context = build.get("context") if isinstance(build, dict) else build
    if isinstance(context, str) and "://" not in context and not context.startswith("git@"):
        if outside_roots(context, base_dir, roots):
            problems.append(
                f"service {svc_name}: build context {context!r} is outside the "
                f"project directory. Keep the build context inside the project."
            )
    return problems


def isolation_problems(
    doc: dict[str, Any], project: str, base_dir: Path, roots: tuple[Path, ...],
) -> list[str]:
    """Return every cross-project isolation violation in a compose document."""
    problems = _check_networks(doc, project) + _check_volumes(doc, project)
    problems += _check_file_refs(doc, base_dir, roots)
    networks = doc.get("networks")
    declared = set(networks) if isinstance(networks, dict) else set()
    services = doc.get("services") or {}
    for svc_name, svc in services.items():
        if isinstance(svc, dict):
            problems += _check_service(svc_name, svc, declared, base_dir, roots)
    return problems
