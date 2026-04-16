"""boxmunge inbox — list and manage bundles in the inbox."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def _parse_bundle_filename(filename: str) -> tuple[str, str] | None:
    """Parse project name and timestamp from a bundle filename.

    Expected format: <project>-<YYYY-MM-DDTHHMMSS......>.tar.gz
    Timestamp is 23 chars (YYYY-MM-DDTHHMMSS + 6 digit microseconds).
    Returns (project, timestamp) or None if the filename doesn't match.
    """
    if not filename.endswith(".tar.gz"):
        return None
    stem = filename.removesuffix(".tar.gz")
    # Timestamp is last 23 chars, preceded by a hyphen separator
    if len(stem) < 25:  # at least 1 char project + '-' + 23 char timestamp
        return None
    timestamp = stem[-23:]
    separator = stem[-24]
    project = stem[:-24]
    if separator != "-" or not project:
        return None
    if not timestamp[:4].isdigit():
        return None
    return project, timestamp


def _format_size(size_bytes: int) -> str:
    """Format bytes as human-readable size."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"


def run_inbox_list(paths: BoxPaths, project_filter: str | None) -> int:
    """List bundles in the inbox. Returns 0."""
    bundles: list[tuple[str, str, int]] = []

    if paths.inbox.exists():
        for entry in paths.inbox.iterdir():
            if entry.is_file() and entry.suffix == ".gz":
                parsed = _parse_bundle_filename(entry.name)
                if parsed:
                    project, timestamp = parsed
                    if project_filter and project != project_filter:
                        continue
                    bundles.append((project, timestamp, entry.stat().st_size))

    if not bundles:
        scope = f" for '{project_filter}'" if project_filter else ""
        print(f"No bundles in inbox{scope}.")
        return 0

    bundles.sort(key=lambda b: b[1], reverse=True)

    print(f"{'PROJECT':<16} {'UPLOADED':<26} {'SIZE':>10}")
    for project, timestamp, size in bundles:
        # Replace T separator with space: 2026-03-31T102300... -> 2026-03-31 102300...
        display_ts = timestamp.replace("T", " ", 1)
        print(f"{project:<16} {display_ts:<26} {_format_size(size):>10}")

    return 0


def run_inbox_clean(
    paths: BoxPaths, project_filter: str | None, yes: bool = False
) -> int:
    """Remove bundles from the inbox. Returns 0."""
    targets: list[Path] = []

    if paths.inbox.exists():
        for entry in paths.inbox.iterdir():
            if entry.is_file() and entry.suffix == ".gz":
                parsed = _parse_bundle_filename(entry.name)
                if parsed:
                    project, _ = parsed
                    if project_filter and project != project_filter:
                        continue
                    targets.append(entry)

    if not targets:
        scope = f" for '{project_filter}'" if project_filter else ""
        print(f"No bundles to clean{scope}.")
        return 0

    if not yes:
        print(f"Will remove {len(targets)} bundle(s):")
        for t in targets:
            print(f"  {t.name}")
        response = input("Proceed? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            return 0

    for t in targets:
        t.unlink()
    print(f"Removed {len(targets)} bundle(s).")
    return 0


def cmd_inbox(args: list[str]) -> None:
    """CLI entry point for inbox command."""
    from boxmunge.paths import BoxPaths
    paths = BoxPaths()

    yes = "--yes" in args
    positional = [a for a in args if not a.startswith("--")]

    if positional and positional[0] == "clean":
        project = positional[1] if len(positional) > 1 else None
        sys.exit(run_inbox_clean(paths, project_filter=project, yes=yes))
    else:
        project = positional[0] if positional else None
        sys.exit(run_inbox_list(paths, project_filter=project))
