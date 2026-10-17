# SPDX-License-Identifier: Apache-2.0
"""Before a release starts: its images, read, and who each service runs as.

Users depend on the images (Config.User, Config.Volumes), so deploy, stage
and promote build their images and pull the missing ones first (`--policy
missing`: what `up` would pull anyway, so a redeploy never updates a
registry image behind container-update's back), then inspect them, decide
each service's user (run_as.effective_user), check what that means for the
service's data (deploy_checks) and record the decision. Profiled services
are included: `up <service>` (restore) starts them from the same record.
"""
from __future__ import annotations

from typing import Any

from boxmunge.commands import deploy_checks
from boxmunge.compose_images import is_platform_image
from boxmunge.docker_containers import ImageFacts, image_facts
from boxmunge.docker_run import run as _run
from boxmunge.log import log_operation, log_warning
from boxmunge.paths import BoxPaths
from boxmunge.release_target import (
    DeployRefused, ReleaseTarget, as_written, compose_users, resolved_services,
)
from boxmunge.run_as import (
    SOURCE_MANIFEST, RunAsError, ServiceUser, declared_user, describe, effective_user,
    read_users, write_users,
)
from boxmunge.userns.offset import RemapError, remap_offset

_BUILD_TIMEOUT = 1800


def build_and_pull(target: ReleaseTarget, services: dict[str, dict]) -> None:
    builds = sorted(n for n, s in services.items() if s.get("build") is not None)
    pulls = sorted(n for n, s in services.items() if s.get("build") is None
                   and isinstance(s.get("image"), str) and not is_platform_image(s["image"]))
    if builds:
        print(f"  Building {', '.join(builds)}...")
        _run([*target.command(), "build", *builds], cwd=target.compose.cwd,
             timeout=_BUILD_TIMEOUT)
    if pulls:
        _run([*target.command(), "pull", "--ignore-buildable", "--policy", "missing", *pulls],
             cwd=target.compose.cwd, timeout=_BUILD_TIMEOUT)


def decide_users(services: dict[str, dict], facts: dict[str, ImageFacts],
                 manifest: dict[str, Any], carried: dict[str, ServiceUser] | None = None,
                 ) -> tuple[dict[str, ServiceUser], list[str]]:
    """(every service's user, warnings). DeployRefused lists every service
    that needs a declaration, so the operator adds them in one pass. A
    rollback passes the record as `carried`: the release it restores may
    predate its services' declarations, and a recorded decision about a
    service's data stands until a deploy makes another."""
    users: dict[str, ServiceUser] = {}
    refusals: list[str] = []
    warnings: list[str] = []
    for name, svc in sorted(services.items()):
        try:
            users[name] = effective_user(name, svc, manifest, facts[name].user)
        except RunAsError as e:
            if carried and name in carried:
                users[name] = carried[name]
                warnings.append(f"service {name}: the restored release does not say who it "
                                f"runs as, so it keeps its recorded user, "
                                f"{describe(carried[name])}")
            else:
                refusals.append(str(e))
    if refusals:
        raise DeployRefused(refusals)
    return users, warnings


def _log_opt_outs(paths: BoxPaths, target: ReleaseTarget, manifest: dict[str, Any],
                  users: dict[str, ServiceUser], component: str) -> None:
    """Root and image declarations are logged with their reason at every
    deploy, as profile: off is."""
    for name, user in sorted(users.items()):
        if user.source == SOURCE_MANIFEST and user.user in (None, "0:0"):
            _value, reason = declared_user(manifest.get("security"),
                                           (manifest.get("services") or {}).get(name))
            log_operation(component, f"service {name} runs as {describe(user)}, reason: "
                          f"{reason}", paths, project=target.project)


def prepare_release_users(paths: BoxPaths, target: ReleaseTarget, manifest: dict[str, Any], *,
                          component: str, rollback: bool = False) -> dict[str, ServiceUser]:
    """Build/pull, inspect, decide every service's user, check, record.
    Raises DeployRefused (nothing recorded), DockerError or RunAsError (the
    record cannot be read)."""
    carried = read_users(paths, target.project, staging=target.staging) if rollback else None
    model, services = resolved_services(target)
    build_and_pull(target, services)
    facts = {name: image_facts(str(svc.get("image"))) for name, svc in services.items()}
    users, warnings = decide_users(as_written(services, compose_users(target)), facts,
                                   manifest, carried)
    try:
        offset = remap_offset(paths)
    except RemapError as e:
        raise DeployRefused([str(e)]) from e
    refusals, data_warnings = deploy_checks.release_problems(
        paths, target, model, services, facts, users, offset)
    for warning in warnings + data_warnings:
        print(f"  WARNING: {warning}")
        log_warning(component, warning, paths, project=target.project)
    if refusals:
        raise DeployRefused(refusals)
    write_users(paths, target.project, users, staging=target.staging)
    _log_opt_outs(paths, target, manifest, users, component)
    return users
