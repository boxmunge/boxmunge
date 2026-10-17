# SPDX-License-Identifier: Apache-2.0
"""What the daemon holds, from Docker itself, not from boxmunge's records.

Every container's `Mounts` (stopped ones included), every volume with its
full metadata, every image, the proxy network's IPAM config, and the
registry's projects. Projects deployed before the binds record, stopped
services and unattached volumes are all covered. Each mount is classified:

  data        read-write bind under projects/: shifted in place
  readable    read-only bind under projects/: must be world-readable
  platform    read-only bind under caddy/ (Caddy's config): world-readable
  system      the system container's binds: it runs in the host namespace
  volume      named volume: moved and shifted
  anonymous   anonymous volume (refused when it holds data)
  tmpfs       nothing to carry
  refuse      any other bind (Caddy logs to stdout; nothing writes caddy/)
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from boxmunge.data_helper import is_anonymous
from boxmunge.docker_run import run as _run
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import load_registered_projects
from boxmunge.release import project_data_dirs
from boxmunge.system_container import CONTAINER_NAME
from boxmunge.userns.offset import docker_info

PROXY_NETWORK = "boxmunge-proxy"
CONTAINERD_STORE = "io.containerd.snapshotter.v1"


@dataclass
class MountEntry:
    type: str
    source: str
    destination: str
    rw: bool
    name: str
    kind: str


@dataclass
class ContainerEntry:
    id: str
    name: str
    compose_project: str
    service: str
    image_id: str
    running: bool
    privileged: bool
    pid: str
    network: str
    ipc: str
    userns: str
    mounts: list[MountEntry] = field(default_factory=list)


@dataclass
class VolumeEntry:
    name: str
    driver: str
    options: dict[str, Any]
    labels: dict[str, str]
    mountpoint: str
    attached: bool
    anonymous: bool
    has_data: bool


@dataclass
class ImageEntry:
    id: str
    tags: list[str]
    size: int
    in_use: bool


@dataclass
class Inventory:
    driver: str
    driver_type: str
    root: str
    server_version: str
    containers: list[ContainerEntry] = field(default_factory=list)
    volumes: list[VolumeEntry] = field(default_factory=list)
    images: list[ImageEntry] = field(default_factory=list)
    network: dict[str, Any] = field(default_factory=dict)
    projects: list[str] = field(default_factory=list)
    record_data: list[str] = field(default_factory=list)
    remapped: bool = False  # the daemon already runs containers in a user namespace

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_json(doc: dict[str, Any]) -> Inventory:
        doc = dict(doc)
        doc["containers"] = [ContainerEntry(**{**c, "mounts": [MountEntry(**m) for m in c["mounts"]]})
                             for c in doc["containers"]]
        doc["volumes"] = [VolumeEntry(**v) for v in doc["volumes"]]
        doc["images"] = [ImageEntry(**i) for i in doc["images"]]
        return Inventory(**doc)

    def data_binds(self) -> list[str]:
        """Every read-write bind source to shift, plus recorded data entries
        and their staging copies that no container mounts right now."""
        mounted = {m.source for c in self.containers for m in c.mounts if m.kind == "data"}
        return sorted(mounted | set(self.record_data))

    def with_running_from(self, earlier: Inventory) -> Inventory:
        """A fresh inventory taken after a partial quiesce keeps who was running."""
        was = {c.id for c in earlier.containers if c.running}
        for c in self.containers:
            c.running = c.running or c.id in was
        return self


def _json(cmd: list[str]) -> list[dict[str, Any]]:
    doc = json.loads(_run(cmd, capture=True).stdout)
    if not isinstance(doc, list):
        raise ValueError(f"{' '.join(cmd[:3])} did not return a list")
    return doc


def _under(path: str, root: Path) -> bool:
    return path == str(root) or path.startswith(str(root).rstrip("/") + "/")


def classify(mount: dict[str, Any], container_name: str, paths: BoxPaths) -> str:
    kind = mount.get("Type")
    if kind == "tmpfs":
        return "tmpfs"
    if kind == "volume":
        return "volume"
    if kind != "bind":
        return "refuse"
    if container_name == CONTAINER_NAME:
        return "system"
    src, rw = os.path.normpath(str(mount.get("Source"))), mount.get("RW") is not False
    if _under(src, paths.projects) and src != str(paths.projects):
        return "data" if rw else "readable"
    if _under(src, paths.caddy) and not rw:
        return "platform"
    return "refuse"


def _container(doc: dict[str, Any], paths: BoxPaths) -> ContainerEntry:
    config, host = doc.get("Config") or {}, doc.get("HostConfig") or {}
    labels = config.get("Labels") or {}
    name = str(doc.get("Name", "")).lstrip("/")
    mounts = [MountEntry(type=str(m.get("Type")), source=os.path.normpath(str(m.get("Source")))
                         if m.get("Source") else "",
                         destination=str(m.get("Destination")), rw=m.get("RW") is not False,
                         name=str(m.get("Name") or ""), kind=classify(m, name, paths))
              for m in doc.get("Mounts") or []]
    return ContainerEntry(
        id=str(doc["Id"]), name=name,
        compose_project=labels.get("com.docker.compose.project", ""),
        service=labels.get("com.docker.compose.service", ""),
        image_id=str(doc.get("Image")), running=bool((doc.get("State") or {}).get("Running")),
        privileged=host.get("Privileged") is True, pid=str(host.get("PidMode") or ""),
        network=str(host.get("NetworkMode") or ""), ipc=str(host.get("IpcMode") or ""),
        userns=str(host.get("UsernsMode") or ""), mounts=mounts)


def _has_data(mountpoint: str) -> bool:
    with os.scandir(mountpoint) as it:
        return next(it, None) is not None


def _record_data(paths: BoxPaths, projects: list[str],
                 containers: list[ContainerEntry]) -> list[str]:
    """Recorded data entries (a stopped or removed service's data) and the
    staging copies of every data entry, mounted or recorded."""
    out = []
    for p in projects:
        project_dir = paths.project_dir(p)
        if not project_dir.is_dir():
            continue
        prefix = str(project_dir) + "/"
        tops = {m.source[len(prefix):].split("/")[0] for c in containers for m in c.mounts
                if m.kind == "data" and m.source.startswith(prefix)}
        recorded = set(project_data_dirs(project_dir).recorded)
        for name in sorted(recorded | {f"{t}-staging" for t in tops | recorded}):
            if os.path.lexists(project_dir / name):
                out.append(str(project_dir / name))
    return out


def _network() -> dict[str, Any]:
    nets = _run(["docker", "network", "ls", "-q", "--filter", f"name=^{PROXY_NETWORK}$"],
                capture=True).stdout.split()
    if not nets:
        return {}
    doc = _json(["docker", "network", "inspect", PROXY_NETWORK])[0]
    return {"driver": doc.get("Driver"), "ipam": doc.get("IPAM") or {},
            "options": doc.get("Options") or {}, "labels": doc.get("Labels") or {}}


def take_inventory(paths: BoxPaths) -> Inventory:
    info = docker_info()
    driver_type = dict(info.get("DriverStatus") or []).get("driver-type", "")
    ids = _run(["docker", "ps", "-aq", "--no-trunc"], capture=True).stdout.split()
    containers = ([_container(d, paths) for d in _json(["docker", "container", "inspect", *ids])]
                  if ids else [])
    names = _run(["docker", "volume", "ls", "-q"], capture=True).stdout.split()
    attached = {m.name for c in containers for m in c.mounts if m.type == "volume"}
    volumes = []
    for v in _json(["docker", "volume", "inspect", *names]) if names else []:
        labels = v.get("Labels") or {}
        volumes.append(VolumeEntry(
            name=v["Name"], driver=v.get("Driver", ""), options=v.get("Options") or {},
            labels=labels, mountpoint=v["Mountpoint"], attached=v["Name"] in attached,
            anonymous=is_anonymous(labels, v["Name"]), has_data=_has_data(v["Mountpoint"])))
    anonymous = {v.name for v in volumes if v.anonymous}
    for c in containers:
        for m in c.mounts:
            if m.type == "volume" and m.name in anonymous:
                m.kind = "anonymous"
    used = {c.image_id for c in containers}
    image_ids = sorted(set(_run(["docker", "image", "ls", "-q", "--no-trunc"],
                                capture=True).stdout.split()))
    images = [ImageEntry(id=d["Id"], tags=sorted(d.get("RepoTags") or []),
                         size=int(d.get("Size") or 0), in_use=d["Id"] in used)
              for d in (_json(["docker", "image", "inspect", *image_ids]) if image_ids else [])]
    projects = sorted(load_registered_projects(paths))
    return Inventory(driver=str(info.get("Driver")), driver_type=driver_type,
                     root=str(info.get("DockerRootDir")),
                     server_version=str(info.get("ServerVersion")),
                     containers=containers, volumes=volumes, images=images, network=_network(),
                     projects=projects, record_data=_record_data(paths, projects, containers),
                     remapped="name=userns" in (info.get("SecurityOptions") or []))
