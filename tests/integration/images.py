# SPDX-License-Identifier: Apache-2.0
"""The registry images the integration tests use, pulled before they run.

Starts never pull (boxmunge refuses a start whose image is not in the local
store), so a module that starts one of these images through boxmunge needs it
pulled first. It must not rely on an earlier module having pulled it: CI runs
the modules in shards, and which modules run before which changes with them.

Before the first test, tests/integration/conftest.py pulls every image in
IMAGES that a selected module names, in its own source, in a helper module
it imports from tests.integration, or in a file of tests/integration it names
(a compose file, a Dockerfile, a script). tests/test_integration_images.py
fails when a file here names an image-like reference that is in neither
IMAGES nor NOT_IMAGES, so a new image cannot be left to luck. The remapped
daemon's modules (userns/) pull their own images after each remap, into the
store the remapped daemon uses, so they are not scanned.
"""
from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent

IMAGES = frozenset({
    "alpine:3.20",
    "busybox:1.36",
    "caddy:2-alpine",
    "debian:trixie",
    "mysql:8.4",
    "nginx:1",
    "nginx:1.25",
    "nginx:1.27-alpine",
    "nginx:alpine",
    "postgres:16",
    "postgres:16-alpine",
    "python:3.13-slim",
    "python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90",
    "python:3.13-slim-trixie",
    "redis:7-alpine",
    "registry:2",
})

# Strings shaped like an image reference that are not one to pull: images
# the tests build or tag themselves, compose and Docker syntax, user:group.
NOT_IMAGES = frozenset({
    "boxmunge-remap:boxmunge-remap",   # user:group
    "boxmunge.invalid/projb/web:latest",  # built by the test
    "container:projb-db-1",            # network_mode
    "deploy:deploy", "root:docker",    # user:group
    "example.com/app:c", "example.com/app:cache",  # never pulled: config only
    "host:port.", "host:repo",         # prose
    "myapp-frontend:3000",             # host:port
    "myapp-web:2",                     # built by the test
    "no-new-privileges:true", "no-new-privileges:true.",  # security_opt
    "ok:1048576", "ok:1114112", "ok:1245184",  # expected output
    "service:db",                      # network_mode
})

IMAGE_LIKE = re.compile(
    r"(?<![\w./:-])((?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*"
    r":[A-Za-z0-9][A-Za-z0-9._-]*(?:@sha256:[0-9a-f]{64})?)(?![\w/:.-])")
SCANNED = (".py", ".sh", ".yml", ".yaml")


def image_like(text: str) -> set[str]:
    return set(IMAGE_LIKE.findall(text))


def scanned_files() -> list[Path]:
    """The files of tests/integration (but this file, and outside userns/)
    that are scanned."""
    return sorted(p for p in HERE.rglob("*") if p.is_file() and "userns" not in p.parts
                  and p != HERE / "images.py"
                  and "__pycache__" not in p.parts
                  and (p.suffix in SCANNED or p.name.startswith("Dockerfile")))


def _helpers(source: str) -> set[Path]:
    """The tests.integration modules a module imports."""
    found = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and node.module == "tests.integration":
            names = [f"tests.integration.{a.name}" for a in node.names]  # a module each
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        elif isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        else:
            names = []
        for name in names:
            if name.startswith("tests.integration.") and not name.startswith(
                    "tests.integration.userns"):
                path = HERE / (name.removeprefix("tests.integration.").replace(".", "/") + ".py")
                if path.is_file() and path != HERE / "images.py":  # names every image
                    found.add(path)
    return found


def named_by(module: Path) -> set[str]:
    """The IMAGES a test module names: itself, conftest.py, the
    tests.integration helpers they import (and theirs), and the other files
    of tests/integration they name."""
    seen: set[Path] = set()
    # conftest.py's fixtures serve every module.
    todo = [module.resolve(), HERE / "conftest.py"]
    while todo:
        path = todo.pop()
        if path in seen:
            continue
        seen.add(path)
        if path.suffix == ".py":
            todo.extend(_helpers(path.read_text()) - seen)
    texts = [p.read_text() for p in seen]
    others = [p for p in scanned_files() if p.suffix != ".py" or p.parent != HERE]
    for path in others:
        if path in seen:
            continue
        rel = path.relative_to(HERE)
        if any(rel.parts[0] in text for text in texts):
            texts.append(path.read_text())
    return {ref for text in texts for ref in image_like(text)} & IMAGES


def ensure(refs: set[str], why: str) -> None:
    """Pull each of refs that the local store lacks; a failed pull fails."""
    for ref in sorted(refs):
        if subprocess.run(["docker", "image", "inspect", ref], capture_output=True,
                          timeout=60, check=False).returncode == 0:
            continue
        pulled = subprocess.run(["docker", "pull", "-q", ref], capture_output=True, text=True,
                                timeout=600, check=False)
        if pulled.returncode != 0:
            raise RuntimeError(f"cannot pull {ref} ({why}): {pulled.stderr.strip()}")
