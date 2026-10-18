# SPDX-License-Identifier: Apache-2.0
"""Phase 0's checks of what the daemon holds (userns.preflight runs them).

Each check appends every offender to the report: a refusal for what would
break the migration or what it would carry wrongly, a note for what the
operator should know.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from boxmunge.paths import BoxPaths
from boxmunge.userns.daemon_config import DEFAULT_DATA_ROOT
from boxmunge.userns.inventory import CONTAINERD_STORE, Inventory, outermost
from boxmunge.userns.layers import LayerScanError, image_high_ids
from boxmunge.userns.shift import Direction, scan_tree
from boxmunge.userns.walk import closed_to_other

MIN_DOCKER = (28, 0)
PLATFORM = frozenset({"caddy", "system"})
_PRIOR_DRIVERS = {("overlay2", ""), ("overlayfs", CONTAINERD_STORE)}


@dataclass
class Report:
    refusals: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    files: int = 0

    @property
    def ok(self) -> bool:
        return not self.refusals

    def text(self) -> str:
        lines = [f"REFUSED: {r}" for r in self.refusals] + [f"NOTE: {n}" for n in self.notes]
        verdict = ("ready" if self.ok else f"not ready: {len(self.refusals)} refusal(s) above")
        return "\n".join(lines + [f"VERDICT: {verdict}"])


def docker_version(inv: Inventory, r: Report) -> None:
    parts = inv.server_version.split(".")
    try:
        found = (int(parts[0]), int(parts[1]))
    except (IndexError, ValueError):
        r.refusals.append(f"cannot read the Docker version {inv.server_version!r}")
        return
    if found < MIN_DOCKER:
        r.refusals.append(f"Docker {inv.server_version} is older than 28.0; upgrade Docker first")


def prior_store(inv: Inventory, r: Report) -> None:
    if inv.remapped:
        r.refusals.append("the daemon already remaps user namespaces; the migration starts "
                          "only from an unremapped daemon (OPERATIONS.md, 'User-namespace "
                          "remapping')")
    if (inv.driver, inv.driver_type) not in _PRIOR_DRIVERS:
        r.refusals.append(f"the daemon stores images with {inv.driver!r} "
                          f"({inv.driver_type or 'graph driver'}); the migration supports "
                          f"overlay2 and the containerd store's overlayfs only")
    if inv.root != DEFAULT_DATA_ROOT:
        r.refusals.append(f"the daemon's root is {inv.root}; the migration supports only "
                          f"{DEFAULT_DATA_ROOT}")


def containers(inv: Inventory, r: Report) -> None:
    ours = set(inv.projects) | PLATFORM
    for c in inv.containers:
        if c.compose_project not in ours:
            what = (f"compose project {c.compose_project!r}" if c.compose_project
                    else "no compose project")
            hint = (f"unstage {c.compose_project.removesuffix('-staging')} first"
                    if c.compose_project.removesuffix("-staging") in inv.projects
                    else "remove it (docker rm) or deploy it as a boxmunge project first")
            r.refusals.append(f"container {c.name} ({what}) is not one boxmunge runs, so the "
                              f"migration cannot carry it: {hint}")
            continue
        for m in c.mounts:
            if m.kind == "refuse":
                r.refusals.append(f"container {c.name} mounts {m.source or m.type} at "
                                  f"{m.destination}, which is neither its project's data nor "
                                  f"Caddy's config; remove the mount and redeploy")


def namespaces(inv: Inventory, r: Report) -> None:
    for c in inv.containers:
        if c.compose_project in PLATFORM:
            continue
        shared = [k for k, v in (("pid", c.pid), ("network_mode", c.network), ("ipc", c.ipc),
                                 ("userns_mode", c.userns)) if v == "host"]
        if c.privileged:
            shared.insert(0, "privileged")
        if shared:
            r.refusals.append(f"container {c.name}: {', '.join(shared)} cannot run on a remapped "
                              f"daemon; remove it from the project and redeploy")


def volumes(inv: Inventory, r: Report, *, forward: bool) -> None:
    by_volume = {m.name: (c, m) for c in inv.containers for m in c.mounts if m.type == "volume"}
    for v in inv.volumes:
        if v.driver != "local" or v.options:
            r.refusals.append(f"volume {v.name}: driver {v.driver!r} with options {v.options}; only "
                              f"plain local volumes can be moved")
        if not (v.anonymous and v.has_data):
            continue
        if v.attached:
            c, m = by_volume[v.name]
            r.refusals.append(
                f"container {c.name} keeps data in anonymous volume {v.name[:12]} at "
                f"{m.destination}; a remapped container would start on a new, empty one. "
                f"Adopt it: boxmunge data adopt {c.compose_project} {c.service}:{m.destination} "
                f"<name>, add <name>:{m.destination} to the service, and redeploy")
        else:
            fate = ("is left in the old root; userns-commit deletes it" if forward
                    else "is deleted with the remapped root")
            r.notes.append(f"dangling anonymous volume {v.name[:12]} "
                           f"({dir_size(Path(v.mountpoint))} bytes) {fate}")


def images(inv: Inventory, r: Report) -> None:
    loose = [img.id[7:19] for img in inv.images if not img.carried]
    if loose:
        r.notes.append(f"{len(loose)} image(s) with no tag that no container runs are not "
                       f"carried across (nothing finds them after a recreate): "
                       f"{', '.join(loose[:10])}" + (" ..." if len(loose) > 10 else ""))
    for img in inv.images:
        if not img.carried:
            continue
        if img.refs:
            r.notes.append(f"{', '.join(img.refs)}: pulled again by digest once its layers are "
                           f"loaded (docker load keeps no digests); its registry must answer "
                           f"during the downtime")
        try:
            high = image_high_ids(img.id)
        except LayerScanError as e:
            r.refusals.append(f"image {', '.join(img.tags or img.refs)}: {e}")
            continue
        if high:
            r.refusals.append(f"image {', '.join(img.tags or img.refs)} has files owned by ids "
                              f"above 65535 "
                              f"({', '.join(high[:5])}), which a remapped daemon cannot load. "
                              f"Rebuild or replace it and redeploy")


def shifted_trees(inv: Inventory, extra_binds: list[str]) -> list[Path]:
    """Every tree the migration shifts: bind data and named volumes' data."""
    trees = [Path(p) for p in outermost(set(inv.data_binds()) | set(extra_binds))]
    return trees + [Path(v.mountpoint) for v in inv.volumes if not v.anonymous]


def data(inv: Inventory, s: int, direction: Direction, r: Report,
         extra_binds: list[str]) -> None:
    for tree in shifted_trees(inv, extra_binds):
        if not os.path.lexists(tree):
            r.notes.append(f"{tree} is mounted but does not exist; nothing to shift")
            continue
        scan = scan_tree(tree, s, direction)
        r.files += scan.entries
        r.refusals += [f"{tree}: {p}" for p in scan.problems]


def readability(paths: BoxPaths, inv: Inventory, r: Report) -> None:
    for source in sorted({m.source for c in inv.containers for m in c.mounts
                          if m.kind in ("readable", "platform")}):
        if source == str(paths.caddyfile):
            continue  # the migration makes it 0644 (engine) and puts it back on rollback
        closed = closed_to_other(Path(source)) if os.path.lexists(source) else []
        if closed:
            r.refusals.append(f"read-only bind {source} has entries a remapped container cannot "
                              f"read (files need o+r, directories o+rx): {', '.join(closed[:10])}"
                              + (f" and {len(closed) - 10} more" if len(closed) > 10 else ""))


def filesystem(inv: Inventory, r: Report) -> None:
    root = Path(inv.root)
    if not (root / "volumes").is_dir():
        r.refusals.append(f"{root}/volumes is not a directory; is {root} the daemon's root?")
        return
    if os.stat(root / "volumes").st_dev != os.stat(root).st_dev:
        r.refusals.append(f"{root}/volumes is on another filesystem than {root}; volumes move "
                          f"by rename, which needs one filesystem")


def dir_size(path: Path) -> int:
    """Bytes on disk under `path`, on its own filesystem only (as du -x): a
    running container's merged overlay mount below it is not counted."""
    try:
        dev = os.lstat(path).st_dev
    except FileNotFoundError:
        return 0
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        kept = []
        for name in dirnames + filenames:
            st = os.lstat(os.path.join(dirpath, name))
            if st.st_dev != dev:
                continue
            total += st.st_blocks * 512
            if name in dirnames:
                kept.append(name)
        dirnames[:] = kept
    return total


def _existing(path: Path) -> Path:
    while not path.exists():
        path = path.parent
    return path


def disk(inv: Inventory, r: Report, images_dir: Path) -> None:
    carried = sum(i.size for i in inv.images if i.carried)
    # The tarballs, then the same layers unpacked; tarballs an interrupted
    # run already wrote need no new space.
    written = sum(t.stat().st_size for t in images_dir.glob("*.tar")) if images_dir.is_dir() else 0
    need = max(0, int(1.1 * 2 * carried) - written)
    free = min(shutil.disk_usage(_existing(images_dir)).free,
               shutil.disk_usage(_existing(Path(inv.root))).free)
    if free < need:
        r.refusals.append(f"{free} bytes free, {need} needed for the image tarballs and their "
                          f"import (+10%)")
