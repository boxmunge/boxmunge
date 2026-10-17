# SPDX-License-Identifier: Apache-2.0
"""A project's release as one compose project runs it, for the steps
between installing a release and starting it (deploy_images,
deploy_checks, deploy_storage, data chown): production from the project
dir, or staging from its slot."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from boxmunge import compose_resolve
from boxmunge.docker import compose_command
from boxmunge.paths import BoxPaths
from boxmunge.staged_release import ComposeTarget, staging_target


class DeployRefused(Exception):
    """The release cannot start as it is; every problem says what to change."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("\n".join(f"- {p}" for p in problems))


@dataclass(frozen=True)
class ReleaseTarget:
    """A project's release as one compose project runs it: production from
    the project dir, or staging from its slot."""
    project: str
    compose: ComposeTarget
    staging: bool = False

    @property
    def compose_project(self) -> str:
        return self.compose.project_name

    def command(self) -> list[str]:
        c = self.compose
        return [*compose_command(c.project_name, list(c.files),
                                 project_directory=c.project_directory, env_file=c.env_file),
                "--profile", "*"]


def production_target(paths: BoxPaths, project: str) -> ReleaseTarget:
    return ReleaseTarget(project, ComposeTarget(
        cwd=paths.project_dir(project), project_name=project,
        files=["compose.yml", "compose.boxmunge.yml"]))


def staging_release_target(paths: BoxPaths, project: str) -> ReleaseTarget:
    return ReleaseTarget(project, staging_target(paths, project), staging=True)


def resolved_services(target: ReleaseTarget) -> tuple[dict[str, Any], dict[str, dict]]:
    """(model, services) of the release with its overlay, every profile in."""
    c = target.compose
    model = compose_resolve.resolve_deployed_config(
        c.cwd, list(c.files), c.project_name, all_profiles=True,
        project_directory=c.project_directory, env_file=c.env_file)
    services = model.get("services") or {}
    return model, {n: s for n, s in services.items() if isinstance(s, dict)}


def compose_users(target: ReleaseTarget) -> dict[str, Any]:
    """{service: its `user:`} from the release's compose.yml alone. The
    resolved model also carries the overlay's `user:`, which is boxmunge's
    own earlier decision; only compose.yml's is the operator's choice."""
    from boxmunge.compose import load_user_compose  # compose imports run_as, which this feeds
    release = target.compose.project_directory or target.compose.cwd
    services = load_user_compose(release / "compose.yml", target.project).get("services") or {}
    return {n: s["user"] for n, s in services.items() if isinstance(s, dict) and "user" in s}


def as_written(services: dict[str, dict], users: dict[str, Any]) -> dict[str, dict]:
    """The resolved services with only compose.yml's own `user:`."""
    out = {}
    for name, svc in services.items():
        svc = {k: v for k, v in svc.items() if k != "user"}
        if name in users:
            svc["user"] = users[name]
        out[name] = svc
    return out
