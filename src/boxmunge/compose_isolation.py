# SPDX-License-Identifier: Apache-2.0
"""Cross-project isolation rules for user compose files.

Every project's compose file runs on the same Docker daemon. These rules
keep one project's compose file from reaching another project: it may
declare and join only its own networks (any alias is fine there: a
project-local network cannot collide with another project's), use only
its own named volumes, and
read host files (secrets, configs, build inputs; see compose_build) only
from inside its own directory. It may not publish ports on the host
either; a port that must be published is declared in the manifest (see
`published_ports`). Nor may it hand a service to anything outside its
containers (`provider`, `models`). The shared `boxmunge-proxy` network is
attached by boxmunge's overlay for routed services; a compose file may
not join it itself, by `networks:` or by `network_mode`, nor join another
container's pid or ipc namespace. Images it builds stay in its own image
namespace (see compose_images).

Unlike the hardening rules, these are not relaxed by `security.profile:
off`: opting a service out of container hardening does not entitle it to
another project's network or data.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from boxmunge.compose_build import build_problems, local_dockerfile
from boxmunge.compose_images import image_problems
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
    """Top-level secrets and configs read host files or the environment of
    whoever runs compose; keep them to files in the project."""
    problems: list[str] = []
    for section in ("secrets", "configs"):
        entries = doc.get(section) or {}
        if not isinstance(entries, dict):
            continue
        for key, decl in entries.items():
            if isinstance(decl, dict) and "environment" in decl:
                problems.append(
                    f"top-level {section} {key!r} reads environment variable "
                    f"{decl['environment']!r} from the platform's own process "
                    f"environment, not the project's. Use a file: inside the "
                    f"project, or `secrets set` for secret values."
                )
                continue
            path = decl.get("file") if isinstance(decl, dict) else None
            if isinstance(path, str) and outside_roots(path, base_dir, roots):
                norm, _ = host_path_forms(path, base_dir)
                problems.append(
                    f"top-level {section} {key!r} reads {norm}, outside the "
                    f"project directory. Keep the file inside the project "
                    f"directory, or use `secrets set` for secret values."
                )
    return problems


_MODELS_PROBLEM = (
    "{where} models: runs AI models through Docker Model Runner, outside the "
    "project's containers, which boxmunge does not manage. Remove it and run "
    "the model server as an ordinary service from an image."
)


# Namespace modes that stay inside the project. `host` is a hardening
# question (compose_service_rules); every other value, `container:<name>`
# above all, joins a namespace outside this compose file. Matched exactly,
# as Docker matches them: `Host` would name a network. `service:<name>`
# stays in the project (Compose refuses a service the project does not
# define) where Compose supports it.
_CONTAINED_MODES: dict[str, tuple[frozenset[str], bool]] = {
    "network_mode": (frozenset({"none", "host"}), True),
    "pid": (frozenset({"host"}), True),
    "ipc": (frozenset({"none", "private", "shareable", "host"}), True),
    "uts": (frozenset({"host"}), False),
    "userns_mode": (frozenset({"host"}), False),
    "cgroup": (frozenset({"host", "private"}), False),
}


def _check_namespace_joins(svc_name: str, svc: dict[str, Any]) -> list[str]:
    """network_mode accepts any Docker network name, and the daemon accepts
    `container:<name>` for pid, ipc and userns_mode."""
    problems: list[str] = []
    for key, (allowed, service_ok) in _CONTAINED_MODES.items():
        mode = svc.get(key)
        if mode is None or (isinstance(mode, str) and (
                mode in allowed or (service_ok and mode.startswith("service:")))):
            continue
        instead = sorted(allowed - {"host"})
        if service_ok:
            instead.append("service:<name> for a service in this file")
        if key == "network_mode":
            instead.insert(0, "the project's own networks (remove it)")
        advice = f"Use {', or '.join(instead)}." if instead else "Remove it."
        problems.append(
            f"service {svc_name}: {key} {mode!r} joins a namespace or network "
            f"outside this compose file, which may be another project's. {advice}"
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
    problems += _check_namespace_joins(svc_name, svc)
    if "provider" in svc:
        problems.append(
            f"service {svc_name}: provider: hands the service to an executable "
            f"on the host, which runs outside any container as whoever runs the "
            f"deploy. Remove it and run the service from an image."
        )
    if "models" in svc:
        problems.append(_MODELS_PROBLEM.format(where=f"service {svc_name}:"))
    problems += build_problems(svc_name, svc.get("build"), base_dir, roots)
    return problems


def isolation_problems(
    doc: dict[str, Any], project: str, base_dir: Path, roots: tuple[Path, ...],
) -> list[str]:
    """Return every cross-project isolation violation in a compose document."""
    problems = _check_networks(doc, project) + _check_volumes(doc, project)
    problems += _check_file_refs(doc, base_dir, roots)
    if doc.get("models"):
        problems.append(_MODELS_PROBLEM.format(where="top-level"))
    networks = doc.get("networks")
    declared = set(networks) if isinstance(networks, dict) else set()
    services = doc.get("services") or {}
    for svc_name, svc in services.items():
        if isinstance(svc, dict):
            problems += _check_service(svc_name, svc, declared, base_dir, roots)
    if isinstance(services, dict):
        dockerfiles = {
            name: local_dockerfile(svc.get("build"), base_dir, roots)
            for name, svc in services.items()
            if isinstance(svc, dict) and svc.get("build") is not None
        }
        problems += image_problems(services, project, dockerfiles)
    return problems
