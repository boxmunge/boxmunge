# SPDX-License-Identifier: Apache-2.0
"""A Compose project's containers, found by their Compose labels.

Compose labels every container it creates with its project and service.
Those labels, not container names, say which containers run a service: a
custom `container_name`, replicas and one-off `run` containers all carry
them, while the `<project>-<service>-1` naming convention holds for none
of those.

Each container records the image it was created from by local image ID,
which is what Docker commands such as `docker tag` accept. A registry
manifest digest is a different value; a bare `sha256:` digest passed to
Docker is looked up as an image ID and not found.

On the containerd image store that ID is the digest of the image's index,
which also holds the build's provenance attestation, so every build has a
new one, even a build entirely from cache. Compose decides whether to
recreate a container by its platform manifest, which a cached build
keeps: a build that moved a name to a new index left the running
container on the old one, and nothing names the old one any more, so the
store drops it (boxmunge 0.11.0 to 0.11.2 rebuilt at every upgrade
restart). The container runs on; its image cannot be inspected.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from boxmunge.docker import COMPOSE_ONEOFF_LABEL as _ONEOFF_LABEL, compose_project_filter
from boxmunge.docker_run import DockerError, run as _run

_SERVICE_LABEL = "com.docker.compose.service"


@dataclass(frozen=True)
class ProjectContainer:
    """One container of a Compose project and the image it runs."""

    name: str
    service: str
    # Local image ID ("sha256:..."): the identity to pass to Docker commands.
    image_id: str
    # Registry references of that image ("repo@sha256:..."), if it was pulled.
    repo_digests: tuple[str, ...]
    running: bool
    # Healthcheck status, or None when the container has no healthcheck.
    health: str | None
    # Started by `docker compose run`, not managed by `up`.
    oneoff: bool
    # Exit code of a container that is not running (None while it runs).
    exit_code: int | None
    # Restart policy name: "no", "always", "unless-stopped", "on-failure".
    restart_policy: str

    @property
    def finished_cleanly(self) -> bool:
        """A one-shot container that ran to completion: it exited 0 and its
        restart policy leaves it exited. Not a failure."""
        return (not self.running and self.exit_code == 0
                and self.restart_policy in ("no", "on-failure"))

    @property
    def image_ref(self) -> str:
        """A reference that names exactly this image, readable where possible:
        its registry repo@digest when it was pulled, else its image ID."""
        return _exact_ref(self.image_id, self.repo_digests)


@dataclass(frozen=True)
class LocalImage:
    """An image in the local image store."""

    image_id: str
    repo_digests: tuple[str, ...]

    @property
    def image_ref(self) -> str:
        """As ProjectContainer.image_ref."""
        return _exact_ref(self.image_id, self.repo_digests)


def _exact_ref(image_id: str, repo_digests: tuple[str, ...]) -> str:
    return repo_digests[0] if repo_digests else image_id


def _inspect(cmd: list[str]) -> list[dict[str, Any]]:
    return _documents(cmd, _run(cmd, capture=True).stdout)


def _documents(cmd: list[str], out: str) -> list[dict[str, Any]]:
    try:
        doc = json.loads(out)
    except json.JSONDecodeError as e:
        raise DockerError(f"{' '.join(cmd[:3])} returned output that is not JSON: {e}") from e
    if not isinstance(doc, list) or not all(isinstance(d, dict) for d in doc):
        raise DockerError(f"{' '.join(cmd[:3])} returned {type(doc).__name__}, not a list")
    return doc


def _name(doc: dict[str, Any]) -> str:
    return str(doc.get("Name") or doc.get("Id") or "?").lstrip("/")


def _service(doc: dict[str, Any]) -> str:
    labels = (doc.get("Config") or {}).get("Labels") or {}
    service = labels.get(_SERVICE_LABEL)
    if not isinstance(service, str) or not service:
        name = _name(doc)
        raise DockerError(
            f"container {name} carries the project's compose label but no "
            f"{_SERVICE_LABEL} label, so its service is unknown. Remove it "
            f"(`docker rm -f {name}`) or relabel it."
        )
    return service


def _container(doc: dict[str, Any], images: dict[str, dict[str, Any]]) -> ProjectContainer:
    name = _name(doc)
    labels = (doc.get("Config") or {}).get("Labels") or {}
    service = _service(doc)
    image_id = doc.get("Image")
    if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
        raise DockerError(f"container {name}: docker reports image {image_id!r}, not an image ID")
    state = doc.get("State") or {}
    health = (state.get("Health") or {}).get("Status")
    running = state.get("Running") is True
    exit_code = state.get("ExitCode")
    if not running and not isinstance(exit_code, int):
        raise DockerError(f"container {name}: docker reports exit code {exit_code!r}")
    policy = ((doc.get("HostConfig") or {}).get("RestartPolicy") or {}).get("Name") or "no"
    return ProjectContainer(
        name=name,
        service=service,
        image_id=image_id,
        repo_digests=tuple(images[image_id].get("RepoDigests") or ()),
        running=running,
        health=health if isinstance(health, str) and health else None,
        oneoff=str(labels.get(_ONEOFF_LABEL, "")).lower() == "true",
        exit_code=None if running else exit_code,
        restart_policy=policy,
    )


def project_volumes(project_name: str) -> list[str]:
    """Names of the Docker volumes labelled as the compose project's.
    Raises DockerError when Docker cannot be asked."""
    listed = _run(["docker", "volume", "ls", "-q", *compose_project_filter(project_name)],
                  capture=True)
    return listed.stdout.split()


def _container_docs(project_name: str) -> list[dict[str, Any]]:
    listed = _run(
        ["docker", "ps", "-a", "--no-trunc", *compose_project_filter(project_name),
         "--format", "{{.ID}}"],
        capture=True,
    )
    ids = listed.stdout.split()
    return _inspect(["docker", "container", "inspect", *ids]) if ids else []


def _local_images(docs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """{image ID: its inspect document} for the images the containers were
    created from that the local image store still has (see the module
    docstring for one that it does not). Raises DockerError for any other
    failure."""
    image_ids = sorted({d.get("Image") for d in docs if isinstance(d.get("Image"), str)})
    if not image_ids:
        return {}
    cmd = ["docker", "image", "inspect", *image_ids]
    result = _run(cmd, capture=True, check=False)
    lines = [e.strip() for e in (result.stderr or "").splitlines() if e.strip()]
    errors = [e for e in lines if "no such image" not in e.lower()]
    if result.returncode != 0 and errors:
        raise DockerError(f"{' '.join(cmd[:3])} failed: {'; '.join(errors)}")
    found = {d.get("Id"): d for d in _documents(cmd, result.stdout or "")
             if d.get("Id") in image_ids}
    # An image counts as gone only when Docker says so; a failure that names
    # nothing must not make a start recreate every container.
    unsaid = [i for i in image_ids if i not in found
              and not any("no such image" in e.lower() and e.endswith(i) for e in lines)]
    if unsaid or (result.returncode != 0 and len(found) == len(image_ids)):
        raise DockerError(f"{' '.join(cmd[:3])} described neither the image nor its absence "
                          f"for {', '.join(unsaid) or 'any image'} (exit "
                          f"{result.returncode}): {'; '.join(lines) or 'no output'}")
    return found


def _image_gone(project_name: str, docs: list[dict[str, Any]]) -> DockerError:
    named = "; ".join(f"{_name(d)} (image {d.get('Image')}, created from "
                      f"{(d.get('Config') or {}).get('Image')})" for d in docs)
    return DockerError(
        f"the local image store no longer has the image these containers of {project_name} "
        f"were created from: {named}. A build replaced the image their name points at "
        f"while they kept running. The project's next start recreates a running one from "
        f"the deployed image: prod-deploy {project_name} (or stage, for its staged copy). "
        f"A stopped one must be removed first (docker rm, as the operator).")


def project_containers(project_name: str) -> list[ProjectContainer]:
    """Every container of a compose project, running or stopped, by name.

    Raises DockerError when Docker cannot be asked: an empty answer must
    mean "no containers", never "could not tell". So does a container whose
    image the local image store no longer has, saying how to recreate it.
    """
    docs = _container_docs(project_name)
    images = _local_images(docs)
    gone = [d for d in docs if isinstance(d.get("Image"), str) and d["Image"] not in images]
    if gone:
        raise _image_gone(project_name, gone)
    return sorted((_container(d, images) for d in docs), key=lambda c: c.name)


def running_without_image(project_name: str) -> dict[str, list[str]]:
    """{service: names of its running containers (`run` one-offs excluded)
    whose image the local image store no longer has}. A start recreates
    them (compose_guard). Raises DockerError when Docker cannot be asked."""
    docs = _container_docs(project_name)
    images = _local_images(docs)
    out: dict[str, list[str]] = {}
    for doc in docs:
        labels = (doc.get("Config") or {}).get("Labels") or {}
        if (doc.get("Image") in images or (doc.get("State") or {}).get("Running") is not True
                or str(labels.get(_ONEOFF_LABEL, "")).lower() == "true"):
            continue
        out.setdefault(_service(doc), []).append(_name(doc))
    return {svc: sorted(names) for svc, names in sorted(out.items())}


def _docker_time(value: str) -> datetime:
    """Docker's RFC 3339 times carry nanoseconds; Python reads microseconds."""
    m = re.fullmatch(r"(.+T\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)", value)
    if m is None:
        raise DockerError(f"unreadable container time {value!r}")
    base, frac, tz = m.groups()
    try:
        return datetime.fromisoformat(base + (frac or ".0")[:7] + ("+00:00" if tz == "Z" else tz))
    except ValueError as e:
        raise DockerError(f"unreadable container time {value!r}: {e}") from e


def created_times(project_name: str) -> dict[str, datetime]:
    """Each container of the compose project (running or not) -> its
    creation time. Raises DockerError when Docker cannot be asked."""
    listed = _run(["docker", "ps", "-a", "--no-trunc", *compose_project_filter(project_name),
                   "--format", "{{.ID}}"], capture=True)
    ids = listed.stdout.split()
    if not ids:
        return {}
    return {str(doc.get("Name", "")).lstrip("/"): _docker_time(str(doc.get("Created", "")))
            for doc in _inspect(["docker", "container", "inspect", *ids])}


@dataclass(frozen=True)
class StartState:
    service: str
    running: bool
    started_at: datetime   # year 1 for a container that never started


def start_states(project_name: str) -> dict[str, StartState]:
    """Each container of the compose project (running or not) -> its service,
    whether it runs and when it last started. Raises DockerError when
    Docker cannot be asked."""
    listed = _run(["docker", "ps", "-a", "--no-trunc", *compose_project_filter(project_name),
                   "--format", "{{.ID}}"], capture=True)
    ids = listed.stdout.split()
    if not ids:
        return {}
    out = {}
    for doc in _inspect(["docker", "container", "inspect", *ids]):
        state = doc.get("State") or {}
        labels = (doc.get("Config") or {}).get("Labels") or {}
        out[str(doc.get("Name", "")).lstrip("/")] = StartState(
            service=str(labels.get(_SERVICE_LABEL, "")), running=state.get("Running") is True,
            started_at=_docker_time(str(state.get("StartedAt", ""))))
    return out


def running_by_service(project_name: str) -> dict[str, list[str]]:
    """{service: names of its running containers}, `run` one-offs excluded."""
    running: dict[str, list[str]] = {}
    for c in project_containers(project_name):
        if c.running and not c.oneoff:
            running.setdefault(c.service, []).append(c.name)
    return running


def local_image(ref: str) -> LocalImage | None:
    """The local image a reference (repo:tag, or a build tag) names now, or
    None when the local image store has no such image.

    Raises DockerError for any other failure, so "not present" is never a
    guess made because Docker could not be asked.
    """
    cmd = ["docker", "image", "inspect", ref]
    result = _run(cmd, capture=True, check=False)
    if result.returncode != 0:
        if "no such image" in (result.stderr or "").lower():
            return None
        raise DockerError(f"docker image inspect {ref} failed: {(result.stderr or '').strip()}")
    try:
        (doc,) = json.loads(result.stdout)
        image_id, digests = doc["Id"], doc.get("RepoDigests") or []
    except (json.JSONDecodeError, ValueError, TypeError, KeyError) as e:
        raise DockerError(f"docker image inspect {ref} returned unexpected output: {e}") from e
    if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
        raise DockerError(f"docker image inspect {ref} reports image ID {image_id!r}")
    return LocalImage(image_id=image_id, repo_digests=tuple(digests))


def container_bind_sources(project_name: str) -> list[tuple[str, bool]]:
    """(host source, read-write) of every bind mount of the project's
    containers, which is what a recreate or `docker compose start` mounts
    again. Raises DockerError when Docker cannot be asked."""
    listed = _run(
        ["docker", "ps", "-a", "--no-trunc", *compose_project_filter(project_name),
         "--format", "{{.ID}}"],
        capture=True,
    )
    ids = listed.stdout.split()
    if not ids:
        return []
    sources = []
    for doc in _inspect(["docker", "container", "inspect", *ids]):
        for mount in doc.get("Mounts") or []:
            if isinstance(mount, dict) and mount.get("Type") == "bind":
                source = mount.get("Source")
                if not isinstance(source, str) or not source:
                    raise DockerError(f"container {doc.get('Name')}: bind mount without a source")
                sources.append((_host_path(source), mount.get("RW") is not False))
    return sources


def container_mounts(project_name: str) -> list[tuple[str, str, dict[str, Any]]]:
    """(container name, compose service, Mounts entry) for every mount of
    every container `up` manages in the compose project, stopped ones
    included (`compose run` one-offs are not the service's)."""
    listed = _run(["docker", "ps", "-a", "--no-trunc", *compose_project_filter(project_name),
                   "--format", "{{.ID}}"], capture=True)
    ids = listed.stdout.split()
    if not ids:
        return []
    out = []
    for doc in _inspect(["docker", "container", "inspect", *ids]):
        labels = (doc.get("Config") or {}).get("Labels") or {}
        if str(labels.get(_ONEOFF_LABEL, "")).lower() == "true":
            continue
        name = str(doc.get("Name", "")).lstrip("/")
        for mount in doc.get("Mounts") or []:
            if isinstance(mount, dict):
                out.append((name, labels.get(_SERVICE_LABEL, ""), mount))
    return out


# Docker Desktop (macOS) reports a host bind source as /host_mnt/<host path>;
# the Linux daemon reports the host path itself.
_DESKTOP_HOST_PREFIX = "/host_mnt/"


def _host_path(source: str) -> str:
    if source.startswith(_DESKTOP_HOST_PREFIX):
        return source[len(_DESKTOP_HOST_PREFIX) - 1:]
    return source


@dataclass(frozen=True)
class ImageFacts:
    """What deciding a service's user needs from its image. `user` is
    Config.User, '' when unset (the containerd store omits the key)."""
    image_id: str
    user: str
    volumes: tuple[str, ...]


def image_facts(ref: str) -> ImageFacts:
    """Inspect a local image. Raises DockerError when it is not present."""
    docs = _inspect(["docker", "image", "inspect", ref])
    if len(docs) != 1:
        raise DockerError(f"docker image inspect {ref} described {len(docs)} images")
    doc = docs[0]
    image_id = doc.get("Id")
    if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
        raise DockerError(f"docker image inspect {ref} reports image ID {image_id!r}")
    config = doc.get("Config") or {}
    user = config.get("User") or ""
    volumes = config.get("Volumes") or {}
    if not isinstance(user, str) or not isinstance(volumes, dict):
        raise DockerError(f"docker image inspect {ref}: unreadable Config.User {user!r} "
                          f"or Config.Volumes {volumes!r}")
    return ImageFacts(image_id=image_id, user=user, volumes=tuple(sorted(volumes)))


def container_users(project_name: str) -> dict[str, str]:
    """{service: Config.User} of the compose project's containers, `run`
    one-offs excluded ('' is the image's default user). Replicas share
    their service's config, so the first one found speaks for it."""
    listed = _run(["docker", "ps", "-a", "--no-trunc", *compose_project_filter(project_name),
                   "--format", "{{.ID}}"], capture=True)
    ids = listed.stdout.split()
    users: dict[str, str] = {}
    for doc in _inspect(["docker", "container", "inspect", *ids]) if ids else []:
        config = doc.get("Config") or {}
        labels = config.get("Labels") or {}
        if str(labels.get(_ONEOFF_LABEL, "")).lower() == "true":
            continue
        service = labels.get(_SERVICE_LABEL)
        if isinstance(service, str) and service:
            users.setdefault(service, str(config.get("User") or ""))
    return users
