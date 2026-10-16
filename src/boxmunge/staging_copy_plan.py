# SPDX-License-Identifier: Apache-2.0
"""Which production data store each staging store is copied from.

A store is a named volume (by its compose key) or a bind-mounted path of
box state (``./uploads``). Sources come from the model production runs,
destinations from the staged release's staging model, so a store the
staged release renames is not silently copied from a volume production
never used. Stores are paired by name. A staged store with no production
store of the same name is left as staging has it only while every
production store is copied somewhere: otherwise it may be a rename, and
the manifest must say where its data comes from::

    staging:
      copy_data:
        sources:
          newdata: proddata   # staged store <- production store
          cache: null         # not copied: staging keeps its own

A store is named as compose.yml names a volume, by the ``name`` of a
``writable.persistent`` entry, or as ``./path`` for a bind mount.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from boxmunge.bind_mounts import project_relative
from boxmunge.bundle import BOXMUNGE_ENTRIES
from boxmunge.compose_mounts import is_bind_entry, volume_source


class StagingDataError(Exception):
    """Production data cannot be copied for staging."""


@dataclass(frozen=True)
class Store:
    kind: str  # "volume" or "bind"
    key: str   # compose volume key, or "./<path>" as production names it
    ref: str   # Docker volume name, or absolute host path

    @property
    def label(self) -> str:
        return f"volume {self.key}" if self.kind == "volume" else self.key


@dataclass(frozen=True)
class CopyPlan:
    pairs: list[tuple[Store, Store]] = field(default_factory=list)  # (source, destination)
    fresh: list[Store] = field(default_factory=list)    # staging stores not copied into
    unused: list[Store] = field(default_factory=list)   # production stores not copied


def copy_sources(manifest: dict[str, Any]) -> dict[str, str | None] | None:
    """``staging.copy_data`` as {staged store: production store or None};
    None when copying is off. Shape errors are the manifest validator's."""
    copy_data = (manifest.get("staging") or {}).get("copy_data")
    if not copy_data:
        return None
    if copy_data is True:
        return {}
    return dict(copy_data.get("sources") or {})


def _volume_name(model: dict[str, Any], key: str, compose_project: str) -> str:
    decl = (model.get("volumes") or {}).get(key)
    if not isinstance(decl, dict):
        raise StagingDataError(f"a service mounts volume {key!r}, which the model does not declare")
    return decl.get("name") or f"{compose_project}_{key}"


def stores(model: dict[str, Any], compose_project: str, project_dir: Path,
           data_entries: set[str], *, staging: bool) -> list[Store]:
    """The data stores a resolved model mounts: volumes, and bind mounts and
    config/secret files in box state.

    ``data_entries`` names the project's box-state entries. For staging, a
    bind store is a path in an entry's ``-staging`` copy, keyed by the
    production path it stands for.
    """
    data_entries = data_entries - set(BOXMUNGE_ENTRIES)
    found: dict[tuple[str, str], Store] = {}
    files: dict[tuple[str, str], Store] = {}

    def bind(source: str, into: dict[tuple[str, str], Store]) -> None:
        rel = project_relative(source, project_dir)
        if rel is None or rel == ".":
            return
        top, _, rest = rel.partition(os.sep)
        if staging:
            if not top.endswith("-staging") or top[:-len("-staging")] not in data_entries:
                return
            top = top[:-len("-staging")]
        elif top not in data_entries:
            return
        key = "./" + "/".join(p for p in (top, rest) if p)
        into[("bind", key)] = Store("bind", key, os.path.normpath(project_dir / rel))

    for svc in (model.get("services") or {}).values():
        for entry in (svc.get("volumes") or []) if isinstance(svc, dict) else []:
            if is_bind_entry(entry):
                bind(volume_source(entry), found)
                continue
            key = entry.get("source") if isinstance(entry, dict) else volume_source(entry)
            if key:  # anonymous volumes belong to their container
                found[("volume", key)] = Store(
                    "volume", key, _volume_name(model, key, compose_project))
    for section in ("configs", "secrets"):
        for decl in (model.get(section) or {}).values():
            if isinstance(decl, dict) and isinstance(decl.get("file"), str):
                bind(decl["file"], files)
    # A config or secret file is its own store even inside a copied
    # directory: Compose needs it in place before staging's containers exist.
    kept = _outermost(list(found.values()))
    kept += [f for k, f in files.items() if k not in found]
    return sorted(kept, key=lambda s: (s.kind, s.key))


def _outermost(found: list[Store]) -> list[Store]:
    """Drop bind stores inside another one: copying the outer copies them."""
    binds = [s.key for s in found if s.kind == "bind"]
    return [s for s in found if s.kind == "volume" or not any(
        s.key.startswith(other + "/") for other in binds)]


def _lookup(stores_: list[Store], name: str, project: str, side: str) -> Store:
    if name.startswith("."):
        wanted = {("bind", "./" + os.path.normpath(name))}
    else:
        wanted = {("volume", name), ("volume", f"{project}_{name}")}
    hits = [s for s in stores_ if (s.kind, s.key) in wanted]
    if len(hits) != 1:
        known = ", ".join(s.label for s in stores_) or "none"
        what = "matches more than one" if hits else "names none"
        raise StagingDataError(
            f"staging.copy_data.sources: {name!r} {what} of the {side} stores "
            f"({known}). Name a volume as compose.yml names it, a "
            f"writable.persistent entry by its name, or a bind mount as ./path.")
    return hits[0]


def plan_copy(prod: list[Store], staging: list[Store], sources: dict[str, str | None],
              project: str) -> CopyPlan:
    """Pair every staging store with its production source (see module doc)."""
    explicit: dict[Store, Store | None] = {}
    for dest_name, src_name in sources.items():
        dest = _lookup(staging, dest_name, project, "staged release's")
        explicit[dest] = None if src_name is None else _lookup(prod, src_name, project, "production")
    by_key = {(s.kind, s.key): s for s in prod}
    pairs: list[tuple[Store, Store]] = []
    fresh: list[Store] = []
    unmatched: list[Store] = []
    for dest in staging:
        if dest in explicit:
            src = explicit[dest]
        else:
            src = by_key.get((dest.kind, dest.key))
            if src is None:
                unmatched.append(dest)
                continue
        if src is None:
            fresh.append(dest)
        else:
            pairs.append((src, dest))
    used = {src for src, _ in pairs}
    unused = [s for s in prod if s not in used]
    if unmatched and unused:
        raise StagingDataError(
            f"the staged release's {', '.join(s.label for s in unmatched)} has no "
            f"production store of the same name, and production's "
            f"{', '.join(s.label for s in unused)} would not be copied anywhere, "
            f"so the store may have been renamed. Say where its data comes from in "
            f"the manifest, e.g. staging: {{copy_data: {{sources: "
            f"{{{_name(unmatched[0], project)}: {_name(unused[0], project)}}}}}}}, "
            f"or set it to null to leave staging's own.")
    return CopyPlan(pairs, fresh + unmatched, unused)


def _name(store: Store, project: str) -> str:
    """How the manifest names a store."""
    return store.key.removeprefix(f"{project}_") if store.kind == "volume" else store.key
