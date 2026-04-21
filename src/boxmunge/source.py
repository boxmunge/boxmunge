"""Source resolution — find the right bundle or git ref to deploy/stage."""
from __future__ import annotations
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


class SourceError(Exception):
    """Raised when source resolution fails."""


def _list_bundles_for_project(project_name: str, paths: BoxPaths) -> list[Path]:
    if not paths.inbox.exists():
        return []
    bundles = []
    prefix = f"{project_name}-"
    for entry in paths.inbox.iterdir():
        try:
            if entry.is_file() and entry.name.startswith(prefix) and entry.name.endswith(".tar.gz"):
                bundles.append(entry)
        except (FileNotFoundError, OSError):
            continue  # file vanished between iterdir() and is_file()
    bundles.sort(key=lambda p: p.name, reverse=True)
    return bundles


def resolve_bundle_source(project_name: str, paths: BoxPaths, ref: str | None = None) -> Path:
    bundles = _list_bundles_for_project(project_name, paths)
    if not bundles:
        raise SourceError(
            f"No bundles for project '{project_name}' in inbox. "
            f"Upload with: scp bundle.tar.gz deploy@<host>:"
        )
    if ref:
        for bundle in bundles:
            if ref in bundle.name:
                return bundle
        raise SourceError(
            f"No bundle matching ref '{ref}' for project '{project_name}'. "
            f"Available: {', '.join(b.name for b in bundles[:5])}"
        )
    if len(bundles) > 1:
        from boxmunge.log import log_warning
        log_warning(
            "inbox",
            f"Multiple bundles for '{project_name}' in inbox, using newest: "
            f"{bundles[0].name} (superseding {len(bundles) - 1} older bundle(s))",
            paths,
            project=project_name,
        )
        # Move superseded bundles to .consumed/
        import shutil
        paths.inbox_consumed.mkdir(parents=True, exist_ok=True)
        for old_bundle in bundles[1:]:
            try:
                shutil.move(str(old_bundle), str(paths.inbox_consumed / old_bundle.name))
            except (FileNotFoundError, OSError):
                pass  # already consumed by another process
    return bundles[0]
