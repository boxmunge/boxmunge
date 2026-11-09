# SPDX-License-Identifier: Apache-2.0
"""The restart policy each container gets from the release it runs.

A pause and a quarantine hold their containers' restart policies at "no"
and save the originals. When a new release's start ends the hold (a fix's
deploy lifting a quarantine, or the deploy or rollback a pause was handed
to), the up has recreated the services that changed; a saved original
belongs to the release before it. So every container gets its release's
own policy, what Compose gives a container it creates, never one saved from
an earlier release.
"""
from __future__ import annotations

from typing import Any

from boxmunge import docker_containers, restart_hold
from boxmunge.paths import BoxPaths
from boxmunge.release_target import production_target, resolved_services

_CONDITIONS = {"none": "no", "any": "always", "on-failure": "on-failure"}


class ReleasePolicyError(ValueError):
    """A service's policy cannot be told, or a container's service is not
    in the release."""


def service_policy(svc: dict[str, Any]) -> str:
    """The restart policy Compose gives a container of ``svc``."""
    if svc.get("restart"):
        return str(svc["restart"])
    rule = (svc.get("deploy") or {}).get("restart_policy") or {}
    condition = rule.get("condition")
    if not condition:
        return "no"
    if condition not in _CONDITIONS:
        raise ReleasePolicyError(f"deploy.restart_policy.condition {condition!r} is not one "
                                 f"of {', '.join(_CONDITIONS)}")
    attempts = rule.get("max_attempts")
    return f"on-failure:{attempts}" if condition == "on-failure" and attempts else \
        _CONDITIONS[condition]


def release_policies(paths: BoxPaths, project: str,
                     services: dict[str, str]) -> dict[str, str]:
    """{container: its release's own restart policy} for ``services``
    ({container: service}). Raises ReleasePolicyError for a service the
    release no longer has, ComposeResolveError, OSError."""
    _model, model = resolved_services(production_target(paths, project))
    gone = sorted({svc for svc in services.values() if svc not in model})
    if gone:
        raise ReleasePolicyError(f"services {', '.join(gone)} are no longer in the release")
    return {name: service_policy(model[svc]) for name, svc in services.items()}


def give_release_policies(paths: BoxPaths, project: str) -> None:
    """Give each of the project's containers its release's own policy. A
    container of a service the release dropped (an orphan the up left)
    keeps its held "no". Raises DockerError, ReleasePolicyError,
    ComposeResolveError, OSError."""
    _model, model = resolved_services(production_target(paths, project))
    services = {c.name: c.service for c in docker_containers.project_containers(project)
                if not c.oneoff and c.service in model}
    restart_hold.release(project, {name: service_policy(model[svc])
                                   for name, svc in services.items()})
