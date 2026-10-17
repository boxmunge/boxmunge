# SPDX-License-Identifier: Apache-2.0
"""Releases, fixtures and observations for the staging slot's real-Docker tests.

Every release runs one busybox service with no network. Each version is
observable from outside: its env (compose `environment`, `env_file` and
`.env` interpolation), its read-only config dir, and a smoke script that
passes only in a container of the same version, so a production container
running the staged release's files (or the reverse) shows up.
"""
from __future__ import annotations

import json
import subprocess
import uuid
from contextlib import ExitStack, contextmanager
from typing import Any
from unittest.mock import patch

import pytest
import yaml

from boxmunge.project_registry import add_project
from tests.bundle_helpers import manifest_text, place_bundle, tree_snapshot
from tests.integration.docker_images import BUSYBOX, docker, ensure_busybox

V1, V2, V3 = ("2026-10-16T090000000000", "2026-10-16T100000000000",
              "2026-10-16T110000000000")
_LOOP = ["sh", "-c", "trap 'exit 0' TERM; while :; do sleep 1; done"]
_CADDY = ("boxmunge.commands.deploy", "boxmunge.staging_bringup", "boxmunge.commands.unstage_cmd",
          "boxmunge.commands.pause_cmd", "boxmunge.commands.resume_cmd",
          "boxmunge.commands.recover_cmd")


def release(project: str, version: str, *, copy_data: bool = False,
            volumes: list[str] | None = None) -> dict[str, str]:
    manifest = yaml.safe_load(manifest_text(project))
    manifest["schema_version"] = 3
    manifest["services"] = {"app": {"internal": True, "writable": {"external": True},
                                    "smoke": "boxmunge-scripts/smoke.sh"}}
    if copy_data:
        manifest["staging"] = {"copy_data": True}
    compose = {"services": {"app": {
        "image": BUSYBOX, "command": _LOOP, "network_mode": "none",
        "env_file": ["./app.env"],
        "environment": {"VERSION": version, "TAG": "${TAG}"},
        "volumes": ["./appconfig:/etc/app:ro", "./data:/data", *(volumes or [])]}}}
    return {"manifest.yml": yaml.safe_dump(manifest), "compose.yml": yaml.safe_dump(compose),
            ".env": f"TAG={version}\n", "app.env": f"FROM_ENV_FILE={version}\n",
            "appconfig/settings": version, "data/.keep": "",
            "boxmunge-scripts/smoke.sh": f'[ "$VERSION" = {version} ] || exit 2\n'}


@contextmanager
def no_caddy():
    """Caddy is not running in the test box; every reload succeeds."""
    with ExitStack() as stack:
        for module in _CADDY:
            stack.enter_context(patch(f"{module}.caddy_reload"))
        yield


def remove(compose_project: str) -> None:
    label = f"label=com.docker.compose.project={compose_project}"
    for ls, rm in ((["ps", "-aq"], ["rm", "-f"]), (["volume", "ls", "-q"], ["volume", "rm"]),
                   (["network", "ls", "-q"], ["network", "rm"])):
        ids = docker(*ls, "--filter", label).split()
        if ids:
            subprocess.run(["docker", *rm, *ids], capture_output=True, check=False)


@contextmanager
def slot_project(paths, versions: dict[str, dict[str, Any]] | None = None):
    """A registered project with V1, V2 and V3 bundles in the inbox
    (keyword arguments for `release` per version); every container, volume
    and network of it and its staging is removed afterwards."""
    ensure_busybox()
    name = f"bmot{uuid.uuid4().hex[:8]}"
    add_project(name, paths)
    for ref, version in ((V1, "v1"), (V2, "v2"), (V3, "v3")):
        place_bundle(paths, name, ref, release(name, version, **(versions or {}).get(ref, {})))
    try:
        yield name
    finally:
        remove(f"{name}-staging")
        remove(name)


@pytest.fixture
def project(paths):
    with slot_project(paths) as name:
        yield name


def containers(compose_project: str) -> dict[str, tuple[str, str]]:
    """Container name -> (ID, StartedAt) for one compose project."""
    ids = docker("ps", "-aq", "--filter",
                 f"label=com.docker.compose.project={compose_project}").split()
    if not ids:
        return {}
    out = {}
    for line in docker("inspect", "--format", "{{.Name}} {{.Id}} {{.State.StartedAt}}",
                       *ids).splitlines():
        name, cid, started = line.split()
        out[name.lstrip("/")] = (cid, started)
    return out


def env(container: str) -> dict[str, str]:
    pairs = json.loads(docker("inspect", "--format", "{{json .Config.Env}}", container))
    return dict(p.split("=", 1) for p in pairs)


def runs(container: str, version: str) -> bool:
    """The container runs `version`: its compose env, env_file, `.env`
    interpolation and config mount all say so."""
    e = env(container)
    config = docker("exec", container, "cat", "/etc/app/settings")
    return (e["VERSION"], e["TAG"], e["FROM_ENV_FILE"], config) == (version,) * 4


def working_dir(container: str) -> str:
    labels = json.loads(docker("inspect", "--format", "{{json .Config.Labels}}", container))
    return labels["com.docker.compose.project.working_dir"]


def production_files(paths, project: str) -> dict[str, bytes | str]:
    """Every path of production's project dir: code, overlay, live.json,
    previous*, data-dirs.json, data. Staging's own entries (the slot and
    the -staging copies) are left out."""
    return {rel: v for rel, v in tree_snapshot(paths.project_dir(project)).items()
            if not rel.startswith(".releases/staged")
            and "-staging" not in rel.split("/", 1)[0]}
