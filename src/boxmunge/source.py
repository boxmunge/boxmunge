"""Source resolution — find the right bundle to deploy or stage.

Inbox bundles are named ``<project>-<timestamp>.tar.gz`` by reception, with
the timestamp ``YYYY-MM-DDTHHMMSSffffff``. A bundle belongs to a project only
when its name is exactly that shape, so ``foo`` never picks up ``foo-bar``'s
bundles.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

_SUFFIX = ".tar.gz"
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{12}")


class SourceError(Exception):
    """Raised when source resolution fails."""


def bundle_timestamp(project_name: str, filename: str) -> str | None:
    """The inbox timestamp if `filename` is one of project_name's bundles."""
    prefix = f"{project_name}-"
    if not (filename.startswith(prefix) and filename.endswith(_SUFFIX)):
        return None
    ts = filename[len(prefix):-len(_SUFFIX)]
    return ts if _TIMESTAMP.fullmatch(ts) else None


def _list_bundles_for_project(project_name: str, paths: BoxPaths) -> list[tuple[str, Path]]:
    """(timestamp, path) for each of the project's inbox bundles, newest first."""
    if not paths.inbox.exists():
        return []
    bundles = []
    for entry in paths.inbox.iterdir():
        ts = bundle_timestamp(project_name, entry.name)
        if ts is None:
            continue
        try:
            if entry.is_file():
                bundles.append((ts, entry))
        except OSError:
            continue  # file vanished between iterdir() and is_file()
    bundles.sort(reverse=True)
    return bundles


def resolve_bundle_source(project_name: str, paths: BoxPaths, ref: str | None = None) -> Path:
    """Pick the bundle to deploy: the newest, or the one `ref` names.

    `ref` is a full bundle name (``myapp-2026-...``, with or without
    ``.tar.gz``) or a prefix of its timestamp. A ref matching several
    bundles is an error. Resolution has no side effects.
    """
    bundles = _list_bundles_for_project(project_name, paths)
    if not bundles:
        raise SourceError(
            f"No bundles for project '{project_name}' in inbox. "
            f"Upload with: scp -O bundle.tar.gz deploy@<host>:"
        )
    if not ref:
        return bundles[0][1]

    wanted = ref.removesuffix(_SUFFIX)
    matches = [
        path for ts, path in bundles
        if path.name.removesuffix(_SUFFIX) == wanted or ts.startswith(wanted)
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise SourceError(
            f"No bundle matching ref '{ref}' for project '{project_name}'. "
            f"Available: {', '.join(p.name for _, p in bundles[:5])}"
        )
    raise SourceError(
        f"Ref '{ref}' matches {len(matches)} bundles for '{project_name}': "
        f"{', '.join(p.name for p in matches[:5])}. Give the full bundle name."
    )


def bundle_ref(bundle_path: Path) -> str:
    """The deploy ref recorded for a bundle: its inbox name without .tar.gz."""
    return bundle_path.name.removesuffix(_SUFFIX)


def consume_bundle(bundle_path: Path, project_name: str, paths: BoxPaths) -> None:
    """Move an installed bundle, and the project's older ones, to ``.consumed/``."""
    from boxmunge.log import log_warning

    consumed_ts = bundle_timestamp(project_name, bundle_path.name)
    if consumed_ts is None:
        raise SourceError(f"{bundle_path.name} is not an inbox bundle of '{project_name}'")
    paths.inbox_consumed.mkdir(parents=True, exist_ok=True)
    shutil.move(str(bundle_path), str(paths.inbox_consumed / bundle_path.name))

    for ts, older in _list_bundles_for_project(project_name, paths):
        if ts >= consumed_ts:
            continue
        try:
            shutil.move(str(older), str(paths.inbox_consumed / older.name))
        except FileNotFoundError:
            continue  # already consumed by another process
        log_warning(
            "inbox",
            f"Superseded older bundle {older.name} (deployed {bundle_path.name})",
            paths, project=project_name,
        )
