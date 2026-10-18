# SPDX-License-Identifier: Apache-2.0
"""What a release's user decisions mean for its data; refusals with guidance.

- D16: Docker copies an image's directory, owner included, into an empty
  volume whenever a container is created on it, so a numeric non-root
  service must find a new or empty volume's target owned by its own uid in
  the image (or absent from it).
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
from boxmunge.image_probe import DirOwner, probe_dir
from boxmunge.paths import BoxPaths
from boxmunge.release_target import ReleaseTarget
from boxmunge.run_as import ServiceUser, describe, identity, read_users

_SHOWN = 10  # unreadable paths listed per mount
_OVERFLOW_UID = 65534
RANGE = 65536


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
                       users: dict[str, ServiceUser], fresh: Callable[[str], bool],
                       probe: Callable[[str, str], DirOwner | None] = probe_dir) -> list[str]:
    """D16, for numeric non-root services' named volumes that are new or
    empty (`fresh`, by volume key): Docker copies the image's directory only
    into an empty volume. One that holds data keeps its own owners, which
    the user-change check looks at."""
    problems = []
    for name, svc in sorted(services.items()):
        ids = users[name].nonroot_ids() if name in users else None
        if ids is None:
            continue
        for m in service_mounts(svc):
            if m.kind != "volume":
                continue
            owner = probe(facts[name].image_id, m.target)
            if owner is not None and owner.uid != ids[0] and fresh(str(m.source)):
                problems.append(
                    f"service {name} mounts volume {m.source} at {m.target}, which the image "
                    f"owns as {owner.uid}:{owner.gid}, but the service runs as "
                    f"{ids[0]}:{ids[1]} ({describe(users[name])}). Docker copies that "
                    f"directory into the volume, owner included, whenever a container is "
                    f"created on it while it is empty, so a one-time chown would not hold. Set its ownership in the Dockerfile "
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
                    f"{name.removeprefix(target.compose_project + '_')}`, then deploy "
                    f"again. If this deploy left its install open (as reported below), "
                    f"run `prod-deploy {target.project} --abandon` before the adopt: while "
                    f"an install is open, the adopt of a running service is refused")
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
        if not offset:
            return uid
        # A host owner outside the remap range is the overflow uid inside.
        return uid - offset if offset <= uid < offset + RANGE else _OVERFLOW_UID
    name = volume_name(model, target.compose_project, str(m.source))
    if volume_labels(name) is None:
        return None
    out = helper_output(f"{target.compose_project}-check", volume(name, "/x", ro=True),
                        "stat -c %u /x").strip()
    if not out.isascii() or not out.isdigit():
        raise ValueError(f"the helper reported owner {out!r} for volume {name}")
    return int(out)


def _change_problem(target: ReleaseTarget, name: str, new: ServiceUser, before: str | None,
                    after: str, data: list[Mount]) -> str:
    where = ", ".join(str(m.source or m.target) for m in data)
    was = f"ran as {before} and now resolves" if before else "resolves"
    head = (f"service {name} {was} to {after} ({describe(new)}), and keeps data in "
            f"{where} that {'the old user' if before else 'another user'} owns. Its files "
            f"would be unwritable.")
    ids = new.nonroot_ids()
    if ids:
        return (f"{head} Either keep the old user (declare `security.user` with it, or "
                f"`security.user: image` with a reason when the image runs as it), or run "
                f"`boxmunge data chown {target.project} {name} {ids[0]}:{ids[1]}` before "
                f"deploying again")
    return (f"{head} {after} is a name, so boxmunge cannot compare it with the data's "
            f"owner: declare `security.user: \"<uid>:<gid>\"` with {after}'s ids and run "
            f"`boxmunge data chown {target.project} {name} <uid>:<gid>` before deploying "
            f"again")


def user_change_problems(paths: BoxPaths, target: ReleaseTarget, model: dict[str, Any],
                         services: dict[str, dict], users: dict[str, ServiceUser],
                         offset: int) -> list[str]:
    """A service whose user changes over data the old user owns; with no
    earlier user to compare (a first deploy, or containers removed), a
    numeric user over data someone else owns."""
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
        numeric = after.isascii() and after.isdigit()
        if before == after or after == "root" or (before is None and not numeric):
            continue
        if numeric:
            owners = [_owner_uid(target, model, m, offset) for m in data]
            if all(uid in (None, int(after)) for uid in owners):
                continue
        problems.append(_change_problem(target, name, new, before, after, data))
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
            try:
                mode = os.lstat(path).st_mode
            except FileNotFoundError:
                continue  # gone since the directory was listed
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
    label = f"{target.compose_project}-check"

    def fresh(key: str) -> bool:
        name = volume_name(model, target.compose_project, key)
        return volume_labels(name) is None or volume_is_empty(label, name)

    refusals = ownership_problems(services, facts, users, fresh)
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


def writable_by_a_container(project: str, source: str, *, below: bool) -> str | None:
    """A read-write bind of one of the project's containers (production's or
    staging's, running or not) that holds `source` (`below`: strictly
    inside it), or None. Such a container could swap a component of the
    path for a link between a check and the helper's use of it."""
    norm = os.path.normpath(source)
    for compose_project in (project, f"{project}-staging"):
        for bound, rw in docker_containers.container_bind_sources(compose_project):
            top = os.path.normpath(bound)
            if rw and (norm.startswith(top + "/") or (not below and norm == top)):
                return top
    return None
