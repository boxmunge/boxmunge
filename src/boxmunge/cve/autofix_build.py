# SPDX-License-Identifier: Apache-2.0
"""Build a patched image: the exact image a service runs, with only the named
OS packages upgraded from the image's own distro repositories.

`probe` asks an image whether it can be patched: a shell and apk or
apt/dpkg in it, and a user the patch can restore. `build_patched` writes a
four-part Dockerfile (FROM the running digest, switch to root, one RUN that
upgrades the named packages and cleans the package caches, switch back to
the image's own user) and builds it from stdin with no build context (it
copies nothing in), so there is no file on disk to swap, without the layer
cache, and checks the result before naming it:

- it is built on the base (the base's layers are its first layers) and
  carries the BASE_LABEL that marks every patched image;
- every package is at least its fixed version, by the distro's own version
  ordering (`dpkg --compare-versions`, `apk version -t`, run in the image).

The patched image is then tagged image_pins.pin_ref(project, service,
<its image ID>), the ID as the start-time pin check reads it
(docker_containers.local_image), and the scratch directory and every
temporary name are removed, whatever happened. A patch is never built on a
patched image: each one starts from the upstream or built image itself.

Everything the builder runs in an image (the probe, the version check) runs
as root with no network, no capabilities and no entrypoint, and never pulls.
The build itself needs the distro mirrors, so it has the build network.

The installed versions come from the image's own dpkg or apk, so a hostile
image can lie about them. That only leaves its own site unpatched, which
its owner could do anyway; accepted.
"""
from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from boxmunge.compose_images import built_image_name
from boxmunge.docker import build_image, tag_image
from boxmunge.docker_containers import local_image
from boxmunge.docker_run import DockerError, run as _run
from boxmunge.image_pins import pin_ref

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from boxmunge.image_pins import ImagePin

# Set on every patched image (the base it was built from): a base carrying
# it is a patched image, which is never patched again.
BASE_LABEL = "boxmunge.autofix.base"
_NO_SHELL = "no shell or package manager in the image"
_PROBE_TIMEOUT = 60
# Debian and Alpine package names: lower case (Alpine allows upper),
# digits and + . _ -, never a leading '-' that a package manager would
# read as an option.
_PACKAGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._-]*")
_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+.~:_-]*")
# Config.User the Dockerfile can restore verbatim (USER expands `$`).
_USER_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*(?::[A-Za-z0-9_][A-Za-z0-9_.-]*)?")
# The tag pin_ref gives a patched image.
_PATCHED_TAG_RE = re.compile(r"boxmunge\.invalid/\S+:autofix-[0-9a-f]{12}")
_AT_DIGEST_RE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")

# Prints the package manager the patch layer would use.
_PROBE_SCRIPT = (
    "if command -v apk >/dev/null 2>&1; then echo apk; "
    "elif command -v apt-get >/dev/null 2>&1 && command -v dpkg-query >/dev/null 2>&1 "
    "&& command -v dpkg >/dev/null 2>&1; then echo apt; else echo none; fi"
)
# Given name/fixed-version pairs, prints `name<TAB>installed<TAB>ok|low|error`
# for each installed package (nothing for one that is not installed);
# `error` is a comparison the distro's tool could not make.
_CHECK_SCRIPTS = {
    "apt": (
        "while [ $# -gt 0 ]; do n=$1; f=$2; shift 2; "
        "dpkg-query -W -f='${db:Status-Status} ${Version}\\n' \"$n\" 2>/dev/null | "
        "while read -r s v; do [ \"$s\" = installed ] || continue; "
        "dpkg --compare-versions \"$v\" ge \"$f\"; case $? in 0) r=ok;; 1) r=low;; "
        "*) r=error;; esac; "
        "printf '%s\\t%s\\t%s\\n' \"$n\" \"$v\" \"$r\"; done; done"
    ),
    "apk": (
        "while [ $# -gt 0 ]; do n=$1; f=$2; shift 2; "
        "apk list --installed \"$n\" 2>/dev/null | while read -r e _; do "
        "v=${e#\"$n\"-}; [ \"$v\" != \"$e\" ] || continue; "
        "case $(apk version -t \"$v\" \"$f\") in '<') r=low;; '='|'>') r=ok;; "
        "*) r=error;; esac; "
        "printf '%s\\t%s\\t%s\\n' \"$n\" \"$v\" \"$r\"; done; done"
    ),
}


class PatchBuildError(Exception):
    """The patched image could not be built, or is not what it must be."""


@dataclass(frozen=True)
class Patchable:
    """The image can be patched with `manager`; `user` is its Config.User
    ('' for the default, root), which the patched image keeps."""
    manager: Literal["apk", "apt"]
    user: str


@dataclass(frozen=True)
class NotPatchable:
    """Why autofix cannot patch the image, for the operator."""
    reason: str


Patchability = Patchable | NotPatchable


@dataclass(frozen=True)
class PatchedImage:
    """The patched image: `ref` (image_pins.pin_ref) names `image_id`;
    `versions` is each upgraded package's installed version."""
    ref: str
    image_id: str
    versions: Mapping[str, str]


def _image_doc(ref: str) -> dict[str, Any]:
    """`docker image inspect` of a local image. Raises DockerError when it is
    absent or the answer is not one image."""
    out = _run(["docker", "image", "inspect", ref], capture=True).stdout
    try:
        (doc,) = json.loads(out)
        config = doc.get("Config") or {}
        layers = (doc.get("RootFS") or {}).get("Layers") or []
    except (json.JSONDecodeError, ValueError, TypeError, AttributeError) as e:
        raise DockerError(f"docker image inspect {ref} returned unexpected output: {e}") from e
    if not isinstance(config, dict) or not isinstance(layers, list) \
            or not isinstance(config.get("User") or "", str):
        raise DockerError(f"docker image inspect {ref}: unreadable Config or RootFS")
    return doc


def _in_image(image: str, script: str, *args: str) -> list[str]:
    """`docker run` of `image` with /bin/sh -c `script` as root, with no
    network, capabilities or pull."""
    return ["docker", "run", "--rm", "--pull", "never", "--network", "none",
            "--user", "0:0", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "64", "--memory", "256m", "--no-healthcheck",
            "--entrypoint", "/bin/sh", image, "-c", script, "sh", *args]


def probe(image_ref: str) -> Patchability:
    """Whether the local image `image_ref` can be patched. Raises
    DockerError when Docker cannot inspect or run it."""
    user = (_image_doc(image_ref).get("Config") or {}).get("User") or ""
    result = _run(_in_image(image_ref, _PROBE_SCRIPT), capture=True, check=False,
                  timeout=_PROBE_TIMEOUT)
    if result.returncode in (126, 127):   # docker run: the shell cannot be run
        return NotPatchable(_NO_SHELL)
    if result.returncode != 0:
        raise DockerError(f"probing {image_ref} for a package manager failed "
                          f"(exit {result.returncode}): {(result.stderr or '').strip()}")
    found = (result.stdout or "").strip().splitlines()
    manager = found[-1] if found else ""
    if manager not in ("apk", "apt"):
        return NotPatchable("no supported package manager (apk or apt) in the image")
    if user and not _USER_RE.fullmatch(user):
        return NotPatchable(f"the image's user {user!r} cannot be restored on a patched "
                            f"image")
    return Patchable(manager=manager, user=user)


def _checked_packages(packages: Mapping[str, str]) -> list[str]:
    if not packages:
        raise PatchBuildError("no packages to upgrade")
    for name, fixed in packages.items():
        if not _PACKAGE_RE.fullmatch(name):
            raise PatchBuildError(f"{name!r} is not a package name")
        if not isinstance(fixed, str) or not _VERSION_RE.fullmatch(fixed):
            raise PatchBuildError(f"{fixed!r}, the fixed version of {name}, is not a "
                                  f"package version")
    return sorted(packages)


def render_dockerfile(from_ref: str, patchability: Patchable,
                      packages: Mapping[str, str], *, base: str | None = None) -> str:
    """The patch layer's Dockerfile: FROM `from_ref`, upgrading only
    `packages` (name: minimum fixed version) with the image's package
    manager, labelled with `base` (default `from_ref`), and ending as the
    image's own user. Raises PatchBuildError for a name or version that is
    not one."""
    names = " ".join(_checked_packages(packages))
    if patchability.manager == "apt":
        script = ("apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y "
                  f"--no-install-recommends --no-remove --only-upgrade {names} && apt-get clean && "
                  "rm -rf /var/lib/apt/lists/*")
    else:
        script = f"apk upgrade --no-cache --no-self-upgrade {names}"
    user = patchability.user
    if user and not _USER_RE.fullmatch(user):
        raise PatchBuildError(f"the image's user {user!r} cannot be restored")
    lines = [f"FROM {from_ref}"]
    if user:
        lines.append("USER 0:0")
    # Exec form: the base's SHELL is not used, and nothing is expanded.
    lines.append(f"RUN {json.dumps(['/bin/sh', '-c', script])}")
    lines.append(f"LABEL {BASE_LABEL}={json.dumps(base or from_ref)}")
    if user:
        lines.append(f"USER {user}")
    return "\n".join(lines) + "\n"


def _refuse_patched_base(base_ref: str, doc: dict[str, Any] | None) -> None:
    tags = [base_ref] + list((doc or {}).get("RepoTags") or [])
    labels = ((doc or {}).get("Config") or {}).get("Labels") or {}
    if any(_PATCHED_TAG_RE.fullmatch(t) for t in tags) or BASE_LABEL in labels:
        raise PatchBuildError(f"{base_ref} is already a patched image; a patch is built "
                              f"from the image the release runs, never from another patch")


def _untag(ref: str) -> None:
    if local_image(ref) is not None:
        _run(["docker", "image", "rm", ref], capture=True)


def _temp_tag_re(project: str, service: str) -> re.Pattern[str]:
    """The temporary names a build of `service` gives its base and result."""
    return re.compile(re.escape(built_image_name(project, service))
                      + r":autofix-(?:build|base)-[0-9a-f]{16}")


def _sweep_temp_tags(project: str, service: str) -> None:
    """Remove, by name only, the temporary names an interrupted build of
    `service` left behind."""
    repo = built_image_name(project, service)
    out = _run(["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}", repo],
               capture=True).stdout or ""
    pattern = _temp_tag_re(project, service)
    for ref in out.split():
        if pattern.fullmatch(ref):
            _run(["docker", "image", "rm", ref], capture=True)


def _cleanup(steps: list[tuple[str, Callable[[], None]]], failed: BaseException | None) -> None:
    """Run every cleanup step, each whatever the others did. Failures are
    notes on `failed` (the error already in flight, which is kept), or
    raised as one PatchBuildError when nothing failed before."""
    problems = []
    for what, step in steps:
        try:
            step()
        except Exception as e:   # every step runs; each failure is reported
            problems.append(f"cleanup could not {what}: {e}")
    if not problems:
        return
    if failed is not None:
        for problem in problems:
            failed.add_note(problem)
        return
    raise PatchBuildError("; ".join(problems))


def check_versions(image: str, patchability: Patchable,
                   packages: Mapping[str, str]) -> dict[str, str]:
    """{package: installed version} in `image`. Raises PatchBuildError,
    naming each package, when one is not installed or is below its fixed
    version by the distro's own ordering."""
    names = _checked_packages(packages)
    pairs = [arg for n in names for arg in (n, packages[n])]
    out = _run(_in_image(image, _CHECK_SCRIPTS[patchability.manager], *pairs),
               capture=True, timeout=_PROBE_TIMEOUT).stdout or ""
    found: dict[str, list[tuple[str, str]]] = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or parts[0] not in packages or parts[2] not in ("ok", "low", "error"):
            raise PatchBuildError(f"unexpected version check output from {image}: {line!r}")
        found.setdefault(parts[0], []).append((parts[1], parts[2]))
    problems, versions = [], {}
    for name in names:
        if name not in found:
            problems.append(f"{name} is not installed")
            continue
        for installed, verdict in found[name]:
            if verdict == "low":
                problems.append(f"{name} {installed} is below the fixed {packages[name]}")
            elif verdict == "error":
                problems.append(f"{name} {installed} cannot be compared with the fixed "
                                f"{packages[name]}")
        versions[name] = found[name][0][0]
    if problems:
        raise PatchBuildError(f"the patched image is not fixed: {'; '.join(problems)}")
    return versions


def _check_built(tag: str, base_layers: list[Any], label: str) -> str:
    """The image ID of the build `tag`, built on `base_layers` with `label`.
    Raises PatchBuildError when it is not."""
    image = local_image(tag)
    if image is None:
        raise PatchBuildError(f"the build left no image named {tag}")
    doc = _image_doc(image.image_id)
    layers = (doc.get("RootFS") or {}).get("Layers") or []
    labels = (doc.get("Config") or {}).get("Labels") or {}
    if not base_layers or layers[:len(base_layers)] != base_layers \
            or len(layers) <= len(base_layers):
        raise PatchBuildError(f"the patched image {image.image_id[:19]} is not built on "
                              f"the base {label}")
    if labels.get(BASE_LABEL) != label:
        raise PatchBuildError(f"the patched image {image.image_id[:19]} lacks its "
                              f"{BASE_LABEL} label")
    return image.image_id


def build_patched(project: str, service: str, base_ref_at_digest: str,
                  packages: Mapping[str, str], patchability: Patchable) -> PatchedImage:
    """Build `service`'s patched image from the local image `base_ref_at_digest`
    (`name@sha256:<digest>`, or the image ID of a built image) with each of
    `packages` upgraded to at least its fixed version, and name it
    pin_ref(project, service, <its image ID>). The caller holds the project
    lock for the whole build: the build first removes the temporary names
    an interrupted build of this service left, which a concurrent build
    would be using. Raises PatchBuildError when the base is a patched
    image, `patchability` is not the base's, or the result fails a check
    (a cleanup failure is a note on it); DockerError when the build fails."""
    _refuse_patched_base(base_ref_at_digest, None)
    if not (_AT_DIGEST_RE.fullmatch(base_ref_at_digest)
            or _IMAGE_ID_RE.fullmatch(base_ref_at_digest)):
        raise PatchBuildError(f"{base_ref_at_digest} is not an exact digest or image ID; a "
                              f"patch is built from exactly the image the service runs")
    doc = _image_doc(base_ref_at_digest)
    _refuse_patched_base(base_ref_at_digest, doc)
    if ((doc.get("Config") or {}).get("User") or "") != patchability.user:
        raise PatchBuildError(f"the probe found user {patchability.user!r}, but "
                              f"{base_ref_at_digest} runs as "
                              f"{(doc.get('Config') or {}).get('User')!r}")
    _sweep_temp_tags(project, service)
    name, token = built_image_name(project, service), secrets.token_hex(8)
    temp_tag, base_tag = f"{name}:autofix-build-{token}", None
    failed: BaseException | None = None
    try:
        from_ref = base_ref_at_digest
        if _IMAGE_ID_RE.fullmatch(base_ref_at_digest):
            # A build cannot start FROM an image ID; it gets a name for the build.
            from_ref = base_tag = f"{name}:autofix-base-{token}"
            tag_image(base_ref_at_digest, base_tag)
        build_image(render_dockerfile(from_ref, patchability, packages,
                                      base=base_ref_at_digest), temp_tag)
        image_id = _check_built(temp_tag, (doc.get("RootFS") or {}).get("Layers") or [],
                                base_ref_at_digest)
        versions = check_versions(image_id, patchability, packages)
        ref = pin_ref(project, service, image_id)
        tag_image(image_id, ref)
        named = local_image(ref)
        if named is None or named.image_id != image_id:
            raise PatchBuildError(f"{ref} does not name the patched image {image_id[:19]}")
        return PatchedImage(ref=ref, image_id=image_id, versions=versions)
    except BaseException as e:
        failed = e
        raise
    finally:
        _cleanup([(f"remove {tag}", lambda tag=tag: _untag(tag))
                  for tag in (temp_tag, base_tag) if tag is not None], failed)


def remove_patched(pin: ImagePin) -> None:
    """Remove the patched image a pin names, by the pin's own ref. Nothing
    to do when the tag is gone; raises PatchBuildError when it names
    another image than the pin's, DockerError when Docker refuses (a
    container still uses it)."""
    image = local_image(pin.ref)
    if image is None:
        return
    if image.image_id != pin.image_id:
        raise PatchBuildError(f"{pin.ref} names another image ({image.image_id[:19]}) than "
                              f"the pin's {pin.image_id[:19]}; not removing it")
    _run(["docker", "image", "rm", pin.ref], capture=True)
