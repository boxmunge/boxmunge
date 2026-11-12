# SPDX-License-Identifier: Apache-2.0
"""Counts what one operation asks of Docker (tests/test_docker_call_counts.py).

Three kinds, as a box pays for them:

- ``compose_config``: each `docker compose config` (0.3 to 0.8 s on a VPS).
  The unit tier's literal stand-in is wrapped, not replaced.
- ``docker_info``: each `docker info`.
- ``other``: every other docker call. The argv at each docker_run.run
  binding and through subprocess.run, and one entry per container or image
  query the unit tier answers from its fake (on a box each of those is one
  docker call or more).

The built-image bookkeeping, which the unit tier stubs out, runs for real
here against a daemon that has one container, the platform's own.
"""
from __future__ import annotations

import subprocess
import sys
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from unittest.mock import patch

from boxmunge import built_images, compose_inventory, docker, docker_containers, docker_run
from boxmunge import restart_hold
from boxmunge.userns import offset
from tests.real_docker_guard import _program

# Read at import, which is collection: before any test's stubs are in place.
_BOOKKEEPING = {name: getattr(built_images, name)
                for name in ("name_running_builds", "untag_old_built_names")}
for _name, _real in _BOOKKEEPING.items():
    if _real.__module__ != built_images.__name__:
        raise RuntimeError(f"built_images.{_name} was already stubbed when "
                           f"tests.docker_call_counter was imported; import it at module level")

_QUERIES = (
    (docker_containers, ("project_containers", "project_volumes", "local_image",
                         "container_bind_sources", "running_without_image", "absent_images",
                         "container_mounts", "container_users", "start_states")),
    (compose_inventory, ("running_inventory",)),
    (restart_hold, ("project_restart_policies", "set_restart_policy")),
)
_PLATFORM_CONTAINER = "c0ffee"
_PLATFORM_INSPECT = "sha256:caddy\tcaddy:2\tboxmunge-caddy\tcaddy\t\t/boxmunge-caddy-1\n"


@dataclass
class DockerCalls:
    compose_config: list[str] = field(default_factory=list)
    docker_info: list[str] = field(default_factory=list)
    other: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {"compose config": len(self.compose_config),
                "docker info": len(self.docker_info), "other": len(self.other)}

    def other_matching(self, *words: str) -> list[str]:
        return [call for call in self.other if all(w in call for w in words)]


def _callers(depth: int = 7) -> str:
    """The boxmunge functions that led here, innermost first: what a failed
    count names, so the new caller is found without a debugger."""
    names, frame = [], sys._getframe(2)
    while frame is not None and len(names) < depth:
        if frame.f_globals.get("__name__", "").startswith("boxmunge"):
            names.append(frame.f_code.co_name)
        frame = frame.f_back
    return " < ".join(names)


def _answer(cmd: list[str]) -> str:
    if cmd[:5] == ["docker", "ps", "-a", "-q", "--no-trunc"]:
        return _PLATFORM_CONTAINER + "\n"
    if cmd[:3] == ["docker", "container", "inspect"]:
        return _PLATFORM_INSPECT
    return ""


@contextmanager
def docker_calls(answer=None):
    """Count until the block ends. ``answer(cmd, **kwargs)`` may give the
    output of a docker call (None: the default, empty but for the
    platform's container)."""
    seen = DockerCalls()
    real_config, real_info, real_run = docker.compose_config, offset.docker_info, subprocess.run

    def config(project_dir, compose_files=None, **kw):
        files = [str(f).rsplit("/", 1)[-1] for f in compose_files or ["compose.yml"]]
        seen.compose_config.append(f"{kw.get('project_name')} {' '.join(files)}: {_callers()}")
        return real_config(project_dir, compose_files, **kw)

    def info():
        seen.docker_info.append(_callers())
        return real_info()

    def run(cmd, *a, **k):
        cmd = [str(part) for part in cmd]
        seen.other.append(" ".join(cmd))
        out = answer(cmd, **k) if answer is not None else None
        return subprocess.CompletedProcess(cmd, 0, _answer(cmd) if out is None else out, "")

    def spawn(cmd, *a, **k):
        if isinstance(cmd, (str, bytes)) or _program(cmd) != "docker":
            return real_run(cmd, *a, **k)
        return run(cmd, **k)

    def query(owner, name):
        real = getattr(owner, name)

        def counted(*a, **k):
            seen.other.append(f"query {name}")
            return real(*a, **k)

        return patch.object(owner, name, counted)

    seams = [patch.object(mod, "_run", run) for name, mod in list(sys.modules.items())
             if name.startswith("boxmunge") and getattr(mod, "_run", None) is docker_run.run]
    with ExitStack() as stack:
        for seam in (patch.object(docker, "compose_config", config),
                     patch.object(offset, "docker_info", info),
                     patch.object(subprocess, "run", spawn),
                     *(patch.object(built_images, n, f) for n, f in _BOOKKEEPING.items()),
                     *(query(owner, n) for owner, names in _QUERIES for n in names),
                     *seams):
            stack.enter_context(seam)
        yield seen
