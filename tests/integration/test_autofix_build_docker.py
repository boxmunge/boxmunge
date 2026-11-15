# SPDX-License-Identifier: Apache-2.0
"""The patch builder with real Docker: real Alpine and Debian images, old
enough that their distro has fixed versions of their packages since, are
patched from their exact digest, keep their runtime contract, and come out
at the fixed versions."""
from __future__ import annotations

import json
import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from boxmunge.cve.autofix_build import (
    BASE_LABEL, NotPatchable, Patchable, PatchBuildError, build_patched, probe,
)
from tests.integration.conftest import skip_no_docker
from tests.integration.docker_images import docker, image_id

pytestmark = [pytest.mark.integration, skip_no_docker]

# Released before later point releases fixed their packages.
_ALPINE = "alpine:3.19.0"
_DEBIAN = "debian:bookworm-20240110-slim"
_CONTRACT = ("User", "Entrypoint", "Cmd", "Env", "WorkingDir", "Healthcheck", "Labels",
             "ExposedPorts")


@pytest.fixture
def made() -> Iterator[list[str]]:
    """Image references the test made, removed after it."""
    refs: list[str] = []
    yield refs
    if refs:
        subprocess.run(["docker", "image", "rm", "-f", *refs], capture_output=True,
                       timeout=120, check=False)


def _build(dockerfile: str, made: list[str], context: Path | None = None) -> str:
    """Build `dockerfile` (from stdin, or with `context`); return its image ID."""
    name = f"bm-autofix-test-{uuid.uuid4().hex[:12]}"
    if context is None:
        docker("build", "-q", "-t", name, "-", stdin=dockerfile)
    else:
        (context / "Dockerfile").write_text(dockerfile)
        docker("build", "-q", "-t", name, str(context))
    made.append(name)
    return image_id(name)


def _config(ref: str) -> dict:
    return json.loads(docker("image", "inspect", "--format", "{{json .Config}}", ref))


def _repo_digest(ref: str) -> str:
    digests = json.loads(docker("image", "inspect", "--format", "{{json .RepoDigests}}", ref))
    return digests[0]


def _sh(image: str, script: str) -> str:
    return docker("run", "--rm", "--network", "none", "--user", "0:0", "--entrypoint",
                  "/bin/sh", image, "-c", script)


def test_patched_image_keeps_config(made) -> None:
    base = _build(f"""FROM {_ALPINE}
RUN adduser -D -u 1234 app
ENV APP_MODE=production GREETING="hello world"
WORKDIR /srv/app
EXPOSE 8080/tcp 9090/udp
LABEL org.example.role=web
HEALTHCHECK --interval=30s --timeout=3s CMD ["/bin/true"]
SHELL ["/bin/false"]
ENTRYPOINT ["/bin/echo", "entry"]
CMD ["serve", "--port", "8080"]
USER app
""", made)
    patchability = probe(base)
    assert patchability == Patchable(manager="apk", user="app")
    patched = build_patched("shop", "web", base, {"busybox": "1.36.1-r16"},
                            patchability)
    made.append(patched.ref)
    before, after = _config(base), _config(patched.ref)
    assert after["Labels"].pop(BASE_LABEL) == base
    for field in _CONTRACT:
        assert after.get(field) == before.get(field), field
    assert docker("image", "inspect", "--format", "{{.Id}}", patched.ref) == patched.image_id


def test_distroless_not_patchable_with_reason(made, tmp_path) -> None:
    (tmp_path / "app").write_text("static binary stand-in\n")
    scratch = _build('FROM scratch\nCOPY app /app\nENTRYPOINT ["/app"]\n', made, tmp_path)
    assert probe(scratch) == NotPatchable("no shell or package manager in the image")
    no_manager = _build(f"FROM {_ALPINE}\nRUN rm /sbin/apk\n", made)
    result = probe(no_manager)
    assert isinstance(result, NotPatchable) and "apk or apt" in result.reason


@pytest.mark.parametrize("image, manager, package, fixed", [
    (_ALPINE, "apk", "busybox", "1.36.1-r16"),
    (_DEBIAN, "apt", "tzdata", "2024a-0+deb12u1"),
])
def test_alpine_and_debian_patch_builds(made, image, manager, package,
                                        fixed) -> None:
    base = _repo_digest(image)
    patchability = probe(base)
    assert patchability == Patchable(manager=manager, user="")
    patched = build_patched("shop", "web", base, {package: fixed}, patchability)
    made.append(patched.ref)
    compare = ("apk version -t" if manager == "apk" else
               "dpkg --compare-versions {} gt {} && echo '>'")
    installed = patched.versions[package]
    old = _sh(base, "apk list --installed busybox | cut -d' ' -f1 | sed 's/^busybox-//'"
              if manager == "apk" else "dpkg-query -W -f='${Version}' tzdata")
    if manager == "apk":
        assert _sh(patched.ref, f"{compare} {installed} {old}") == ">"
    else:
        assert _sh(patched.ref, compare.format(installed, old)) == ">"
    assert _config(patched.ref)["Labels"][BASE_LABEL] == base


def test_a_version_still_below_the_fix_fails_naming_it(made) -> None:
    base = _repo_digest(_ALPINE)
    before = set(docker("image", "ls", "-q", "--no-trunc").split())
    with pytest.raises(PatchBuildError, match="busybox .* is below the fixed 99"):
        build_patched("shop", "web", base, {"busybox": "99"}, probe(base))
    assert set(docker("image", "ls", "-q", "--no-trunc").split()) <= before
