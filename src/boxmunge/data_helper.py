# SPDX-License-Identifier: Apache-2.0
"""The helper container: every data operation that needs container-side ownership.

Deploy cannot read or change files a container owns: on a remapped box they
belong to host uid S+N, and on any box a 0600 file of uid 999 is closed to
deploy. Copies, chowns and deletes of such data run in a short-lived
container from the box's own boxmunge-system image (digest-pinned base,
built locally by install.sh; nothing is pulled: --pull never). It runs in
the daemon's namespace, remapped when the daemon is (boxmunge never opts
a container out of it), as container root, with no network, a read-only rootfs and only
the capabilities a copy needs. A missing -v source is created by the
daemon, owned by container root. Each run is named and force-removed:
`docker run --rm` alone outlives an interrupted boxmunge, whose signals
reach only the CLI.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import stat
import uuid
from pathlib import Path

from boxmunge.compose_images import built_image_name
from boxmunge.docker_run import DockerError, run as _run

# "system" is a reserved project name, so no project's build owns this name.
HELPER_IMAGE = built_image_name("system", "system")
_TIMEOUT = 1800
_CAPS = ("CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID")
_BUILD_HINT = "docker compose -f /opt/boxmunge/system/compose.yml build"
# Empty /x, hidden entries included, and prove it is empty.
EMPTY_X = 'rm -rf /x/* /x/.[!.]* /x/..?* && [ -z "$(ls -A /x)" ]'
_EMPTY_RC, _NOT_EMPTY_RC = 0, 3


class HelperError(DockerError):
    """The helper image is missing, or a helper run did not do its job."""


def helper_argv(name: str, mounts: list[str], script: str) -> list[str]:
    caps = [arg for cap in _CAPS for arg in ("--cap-add", cap)]
    return ["docker", "run", "--rm", "--name", name, "--pull", "never",
            "--user", "0:0", "--network", "none", "--read-only",
            "--cap-drop", "ALL", *caps, "--security-opt", "no-new-privileges",
            "--pids-limit", "64", "--entrypoint", "sh", *mounts,
            HELPER_IMAGE, "-c", script]


def run_helper(label: str, mounts: list[str], script: str, *, check: bool = True,
               timeout: int = _TIMEOUT) -> int:
    """Run `script` in the helper with `mounts`; return its exit code."""
    name = f"boxmunge-{label}-{uuid.uuid4().hex[:8]}"
    try:
        return _run(helper_argv(name, mounts, script), capture=True, check=check,
                    timeout=timeout).returncode
    except DockerError as e:
        if "no such image" in str(e).lower():
            raise HelperError(f"the helper image {HELPER_IMAGE} is missing; it is the "
                              f"boxmunge-system image. Build it: {_BUILD_HINT}") from e
        raise
    finally:
        try:
            _run(["docker", "rm", "-f", name], capture=True)
        except DockerError as e:
            if "no such container" not in str(e).lower():
                raise


def bind(host: Path, at: str, *, ro: bool = False) -> list[str]:
    """A -v bind mount (the daemon creates a missing host path)."""
    return ["-v", f"{host}:{at}" + (":ro" if ro else "")]


def volume(name: str, at: str, *, ro: bool = False) -> list[str]:
    return ["--mount", f"type=volume,src={name},dst={at}" + (",readonly" if ro else "")]


def empty_dir(label: str, path: Path) -> None:
    run_helper(label, bind(path, "/x"), EMPTY_X)


def copy_into_volume(label: str, src: str, dst: str) -> None:
    """Replace volume `dst`'s contents with a copy of `src`, owners kept."""
    run_helper(label, [*volume(src, "/src", ro=True), *volume(dst, "/dst")],
               EMPTY_X.replace("/x", "/dst") + " && cp -a /src/. /dst/")


def volume_is_empty(label: str, name: str) -> bool:
    rc = run_helper(label, volume(name, "/x", ro=True),
                    f'[ -z "$(ls -A /x)" ] && exit {_EMPTY_RC} || exit {_NOT_EMPTY_RC}',
                    check=False)
    if rc not in (_EMPTY_RC, _NOT_EMPTY_RC):
        raise HelperError(f"could not tell whether volume {name} is empty (exit {rc})")
    return rc == _EMPTY_RC


def chown_at(label: str, mounts: list[str], target: str, uid: int, gid: int, *,
             recursive: bool) -> None:
    flag = "-R " if recursive else ""
    run_helper(label, mounts, f"chown -h {flag}{uid}:{gid} {shlex.quote(target)}")


def container_owned_dirs(root: Path) -> list[Path]:
    """The top-most directories at or under `root` that the calling user
    does not own, found without following symlinks. Deploy can unlink
    everything else; the helper empties these first. Root needs none: it
    removes anything itself, and on a remapped box the helper could not
    empty a directory holding deploy's (unmapped) files."""
    me = os.geteuid()
    if me == 0:
        return []
    found: list[Path] = []
    stack = [root]
    while stack:
        path = stack.pop()
        st = os.lstat(path)
        if not stat.S_ISDIR(st.st_mode):
            continue
        if st.st_uid != me:
            found.append(path)
            continue
        with os.scandir(path) as it:
            stack.extend(Path(e.path) for e in it if e.is_dir(follow_symlinks=False))
    return sorted(found)


_ANONYMOUS_NAME = re.compile(r"[0-9a-f]{64}")


def is_anonymous(labels: dict | None, name: str) -> bool:
    """An anonymous volume: Docker's own marker, or Docker's 64-hex name with
    no Compose volume label. A hand-made named volume (an `external:` one)
    is not anonymous, whatever its labels."""
    labels = labels or {}
    return "com.docker.volume.anonymous" in labels or (
        "com.docker.compose.volume" not in labels and bool(_ANONYMOUS_NAME.fullmatch(name)))


def volume_labels(name: str) -> dict | None:
    """A volume's labels, or None when it does not exist."""
    try:
        out = _run(["docker", "volume", "inspect", "--format", "{{json .Labels}}", name],
                   capture=True).stdout
    except DockerError as e:
        if "no such volume" in str(e).lower():
            return None
        raise
    labels = json.loads(out)
    if labels is not None and not isinstance(labels, dict):
        raise DockerError(f"docker volume inspect {name}: labels are not an object: {out!r}")
    return labels or {}


def _compose_version() -> str:
    out = _run(["docker", "compose", "version", "--short"], capture=True).stdout.strip()
    if not out:
        raise DockerError("docker compose version --short printed nothing")
    return out.removeprefix("v")


def compose_volume_labels(compose_project: str, key: str) -> list[str]:
    """`--label` arguments that make Compose adopt a volume as its own
    (Compose >= 2.35 adopts these without its config-hash label)."""
    labels = {"com.docker.compose.project": compose_project,
              "com.docker.compose.volume": key,
              "com.docker.compose.version": _compose_version()}
    return [arg for k, v in labels.items() for arg in ("--label", f"{k}={v}")]

