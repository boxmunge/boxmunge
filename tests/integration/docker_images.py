# SPDX-License-Identifier: Apache-2.0
"""Tiny local images and Compose projects for the deployed-inventory tests.

Each test image is a one-line build on busybox with its own label, so it has
its own image ID; nothing is pushed or pulled except busybox itself.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

BUSYBOX = "busybox:1.36"


def docker(*args: str, cwd: Path | None = None, stdin: str | None = None) -> str:
    out = subprocess.run(["docker", *args], cwd=cwd, input=stdin, capture_output=True,
                         text=True, timeout=300, check=False)
    if out.returncode != 0:
        raise AssertionError(f"docker {' '.join(args)} failed:\n{out.stderr}")
    return out.stdout.strip()


def ensure_busybox() -> str:
    """Pull busybox once; return its image ID. It carries a registry RepoDigest."""
    if subprocess.run(["docker", "image", "inspect", BUSYBOX], capture_output=True,
                      check=False).returncode != 0:
        docker("pull", "-q", BUSYBOX)
    return image_id(BUSYBOX)


def build_image(tag: str, label: str, extra: str = "") -> str:
    """Build a busybox-based image with its own ID; return that ID."""
    ensure_busybox()
    docker("build", "-q", "-t", tag, "-", stdin=f"FROM {BUSYBOX}\nLABEL bm.test={label}\n{extra}")
    return image_id(tag)


def image_id(ref: str) -> str:
    return docker("image", "inspect", "--format", "{{.Id}}", ref)


def container_image_ids(project: str, service: str) -> set[str]:
    names = docker("ps", "-aq", "--filter", f"label=com.docker.compose.project={project}",
                   "--filter", f"label=com.docker.compose.service={service}").split()
    return {docker("inspect", "--format", "{{.Image}}", n) for n in names}


def compose(project_dir: Path, project: str, *args: str) -> str:
    return docker("compose", "-p", project, *args, cwd=project_dir)


def tear_down(project_dir: Path, project: str, tags: list[str]) -> None:
    subprocess.run(["docker", "compose", "-p", project, "--profile", "*", "down",
                    "--remove-orphans", "-t", "0"], cwd=project_dir,
                   capture_output=True, timeout=120, check=False)
    if tags:
        subprocess.run(["docker", "image", "rm", "-f", *tags], capture_output=True,
                       timeout=120, check=False)
