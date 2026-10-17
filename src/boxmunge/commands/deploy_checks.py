# SPDX-License-Identifier: Apache-2.0
"""What a release's user decisions mean for its data; refusals with guidance.

- D16: Docker copies an image's directory, owner included, into an empty
  volume at every create, so a numeric non-root service must find its
  volume targets owned by its own uid in the image (or absent from it).
- D17: data in an anonymous volume survives only while Compose hands it
  from a container to its replacement. Refused on a remapped box, warned
  about before the migration; a release that would swap a non-empty one
  for a new, empty named volume is refused on any box.
- A service whose user changes while its data belongs to the old one would
  find its files unwritable.
- On a remapped box a container reads deploy-owned files through the
  "other" bits only, so read-only bind sources must be world-readable.

Staging checks its own images (D16, D17, readability); the replacement
and user-change checks guard production's data and run when promote
deploys the release there.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable

from boxmunge import docker_containers
from boxmunge.data_helper import (
    helper_output, is_anonymous, volume, volume_is_empty, volume_labels,
)
from boxmunge.docker_containers import ImageFacts
from boxmunge.image_probe import RANGE, DirOwner, probe_dir
from boxmunge.paths import BoxPaths
from boxmunge.release_target import ReleaseTarget
from boxmunge.run_as import ServiceUser, describe, identity, read_users

_SHOWN = 10  # unreadable paths listed per mount


@dataclass(frozen=True)
class Mount:
    kind: str           # bind | volume | anonymous | tmpfs
    target: str
    source: str | None  # host path (bind) or the model's volume key (volume)
    read_only: bool


def _short(entry: str) -> Mount:
    parts = entry.split(":")
    if len(parts) == 1:
        return Mount("anonymous", parts[0], None, False)
    ro = len(parts) > 2 and "ro" in parts[2].split(",")
    kind = "bind" if parts[0].startswith(("/", ".", "~")) else "volume"
    return Mount(kind, parts[1], parts[0], ro)


def service_mounts(svc: dict[str, Any]) -> list[Mount]:
    """A resolved service's mounts (Compose resolves them to long syntax;
    the short forms are read too)."""
    out = []
    for entry in svc.get("volumes") or []:
        if isinstance(entry, str):
            out.append(_short(entry))
        elif isinstance(entry, dict) and isinstance(entry.get("target"), str):
            kind, ro = entry.get("type"), entry.get("read_only") is True
            if kind == "volume":
                out.append(Mount("volume" if entry.get("source") else "anonymous",
                                 entry["target"], entry.get("source"), ro))
            elif kind == "bind":
                out.append(Mount("bind", entry["target"], entry.get("source"), ro))
            elif kind == "tmpfs":
                out.append(Mount("tmpfs", entry["target"], None, False))
    for entry in svc.get("tmpfs") or []:
        if isinstance(entry, str):
            out.append(Mount("tmpfs", entry.split(":", 1)[0], None, False))
    return out


def persistent(mounts: list[Mount]) -> list[Mount]:
    """The mounts that keep a service's data: named volumes and read-write binds."""
    return [m for m in mounts if m.kind == "volume" or (m.kind == "bind" and not m.read_only)]


def volume_name(model: dict[str, Any], compose_project: str, key: str) -> str:
    decl = (model.get("volumes") or {}).get(key)
    name = decl.get("name") if isinstance(decl, dict) else None
    return name if isinstance(name, str) else f"{compose_project}_{key}"


def ownership_problems(services: dict[str, dict], facts: dict[str, ImageFacts],
                       users: dict[str, ServiceUser], offset: int,
                       probe: Callable[[str, str, int], DirOwner | None] = probe_dir) -> list[str]:
    """D16, for numeric non-root services' named volumes."""
    problems = []
    for name, svc in sorted(services.items()):
        ids = users[name].nonroot_ids() if name in users else None
        if ids is None:
            continue
        for m in service_mounts(svc):
            if m.kind != "volume":
                continue
            owner = probe(facts[name].image_id, m.target, offset)
            if owner is not None and owner.uid != ids[0]:
                problems.append(
                    f"service {name} mounts volume {m.source} at {m.target}, which the image "
                    f"owns as {owner.uid}:{owner.gid}, but the service runs as "
                    f"{ids[0]}:{ids[1]} ({describe(users[name])}). Docker copies that "
                    f"directory into the volume, owner included, at every create, so a "
                    f"one-time chown would not hold. Set its ownership in the Dockerfile "
                    f"(`RUN chown {ids[0]}:{ids[1]} {m.target}`) or declare security.user")
    return problems


def anonymous_findings(project: str, services: dict[str, dict],
                       facts: dict[str, ImageFacts]) -> list[str]:
    """D17: data paths no named mount covers (compose `- /path` entries and
    image VOLUMEs)."""
    found = []
    for name, svc in sorted(services.items()):
        mounts = service_mounts(svc)
        covered = {m.target for m in mounts if m.kind != "anonymous"}
        anon = {m.target for m in mounts if m.kind == "anonymous"}
        anon |= set(facts[name].volumes if name in facts else ())
        for path in sorted(anon - covered):
            found.append(
                f"service {name} keeps data in an anonymous volume at {path}, which a "
                f"migration, a `compose down -v` or a recreate elsewhere loses. Copy it "
                f"into a named volume (boxmunge data adopt {project} {name}:{path} "
                f"<name>), then mount <name>:{path} (compose.yml, or writable.persistent) "
                f"and deploy. For scratch space, use writable.ephemeral instead")
    return found


def replacement_problems(target: ReleaseTarget, model: dict[str, Any],
                         services: dict[str, dict]) -> list[str]:
    """A running container's non-empty anonymous volume about to be swapped
    for a named volume that is new or empty."""
    problems = []
    label = f"{target.compose_project}-check"
    for _cname, svc_name, m in docker_containers.container_mounts(target.compose_project):
        if m.get("Type") != "volume" or svc_name not in services:
            continue
        old = str(m.get("Name") or "")
        if not is_anonymous(volume_labels(old), old):
            continue
        for new in service_mounts(services[svc_name]):
            if new.kind != "volume" or new.target != m.get("Destination"):
                continue
            name = volume_name(model, target.compose_project, str(new.source))
            fresh = volume_labels(name) is None or volume_is_empty(label, name)
            if fresh and not volume_is_empty(label, old):
                problems.append(
                    f"service {svc_name}'s container keeps data in an anonymous volume at "
                    f"{new.target}; this release mounts the named volume {name} there, which "
                    f"is empty, so the service would start without its data. Run "
                    f"`boxmunge data adopt {target.project} {svc_name}:{new.target} "
                    f"{name.removeprefix(target.compose_project + '_')}` first, then deploy "
                    f"again")
    return problems


def _owner_uid(target: ReleaseTarget, model: dict[str, Any], m: Mount,
               offset: int) -> int | None:
    """Container-view uid owning a persistent mount's top, or None when it
    does not exist yet."""
    if m.kind == "bind":
        try:
            uid = os.lstat(str(m.source)).st_uid
        except FileNotFoundError:
            return None
        return uid - offset if offset and offset <= uid < offset + RANGE else uid
    name = volume_name(model, target.compose_project, str(m.source))
    if volume_labels(name) is None:
        return None
    out = helper_output(f"{target.compose_project}-check", volume(name, "/x", ro=True),
                        "stat -c %u /x").strip()
    if not out.isascii() or not out.isdigit():
        raise ValueError(f"the helper reported owner {out!r} for volume {name}")
    return int(out)


def user_change_problems(paths: BoxPaths, target: ReleaseTarget, model: dict[str, Any],
                         services: dict[str, dict], users: dict[str, ServiceUser],
                         offset: int) -> list[str]:
    recorded = read_users(paths, target.project, staging=target.staging)
    running = docker_containers.container_users(target.compose_project)
    problems = []
    for name, new in sorted(users.items()):
        data = persistent(service_mounts(services.get(name) or {}))
        if not data:
            continue
        before = (recorded[name].runs_as() if name in recorded
                  else identity(running[name]) if name in running else None)
        after = new.runs_as()
        if before is None or before == after or after == "root":
            continue
        if after.isascii() and after.isdigit():
            owners = [_owner_uid(target, model, m, offset) for m in data]
            if all(uid in (None, int(after)) for uid in owners):
                continue
        ids = new.nonroot_ids()
        chown = (f"boxmunge data chown {target.project} {name} {ids[0]}:{ids[1]}"
                 if ids else f"boxmunge data chown {target.project} {name} <uid>:<gid>")
        where = ", ".join(str(m.source or m.target) for m in data)
        problems.append(
            f"service {name} ran as {before} and now resolves to {after} ({describe(new)}), "
            f"and keeps data in {where}. Its files would be unwritable. Either declare "
            f"`security.user: image` with a reason, or add USER to the Dockerfile (or "
            f"`security.user: \"<uid>:<gid>\"`) and run `{chown}` before deploying again")
    return problems


def unreadable_entries(source: str) -> list[str]:
    """What a container reaching `source` through the "other" bits cannot
    read: files without o+r, directories without o+rx (links are skipped;
    the bind checks refuse them on the way to a source)."""
    st = os.lstat(source)
    if not os.path.isdir(source) or os.path.islink(source):
        return [source] if st.st_mode & 0o004 == 0 else []
    closed = [source] if st.st_mode & 0o005 != 0o005 else []
    for dirpath, dirnames, filenames in os.walk(source):
        for entry, need in [*((d, 0o005) for d in dirnames), *((f, 0o004) for f in filenames)]:
            path = os.path.join(dirpath, entry)
            mode = os.lstat(path).st_mode
            if not os.path.islink(path) and mode & need != need:
                closed.append(path)
    return closed


def readability_problems(services: dict[str, dict]) -> list[str]:
    problems = []
    for name, svc in sorted(services.items()):
        for m in service_mounts(svc):
            if not (m.kind == "bind" and m.read_only and m.source
                    and os.path.lexists(m.source)):
                continue
            closed = unreadable_entries(m.source)
            if closed:
                more = f" and {len(closed) - _SHOWN} more" if len(closed) > _SHOWN else ""
                problems.append(
                    f"service {name} mounts {m.source} read-only, but a remapped container "
                    f"reads it through the 'other' permission bits and cannot read: "
                    f"{', '.join(closed[:_SHOWN])}{more}. Make its files o+r and its "
                    f"directories o+rx (chmod -R o+rX {m.source})")
    return problems


def release_problems(paths: BoxPaths, target: ReleaseTarget, model: dict[str, Any],
                     services: dict[str, dict], facts: dict[str, ImageFacts],
                     users: dict[str, ServiceUser], offset: int) -> tuple[list[str], list[str]]:
    """(refusals, warnings) for a release about to start."""
    refusals = ownership_problems(services, facts, users, offset)
    if offset:
        refusals += readability_problems(services)
    anonymous = anonymous_findings(target.project, services, facts)
    warnings: list[str] = []
    if offset:
        refusals += anonymous
    else:
        warnings += [f"{a} (until then it will block userns-migrate)" for a in anonymous]
    if not target.staging:
        refusals += replacement_problems(target, model, services)
        refusals += user_change_problems(paths, target, model, services, users, offset)
    return refusals, warnings
