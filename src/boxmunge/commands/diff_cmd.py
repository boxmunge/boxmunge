"""boxmunge diff <project> — preview what a deploy would change."""
from __future__ import annotations

import filecmp
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.bundle import extract_bundle
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.source import resolve_bundle_source, SourceError

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def _compare_dirs(current: Path, incoming: Path) -> tuple[list[str], list[str], list[str]]:
    """Compare two directories recursively.
    Returns (changed, added, removed) as lists of relative path strings.
    """
    changed, added, removed = [], [], []

    current_files = set()
    if current.exists():
        for f in current.rglob("*"):
            if f.is_file():
                current_files.add(str(f.relative_to(current)))

    incoming_files = set()
    for f in incoming.rglob("*"):
        if f.is_file():
            incoming_files.add(str(f.relative_to(incoming)))

    for rel in sorted(incoming_files & current_files):
        if not filecmp.cmp(current / rel, incoming / rel, shallow=False):
            changed.append(rel)

    for rel in sorted(incoming_files - current_files):
        added.append(rel)

    # Skip boxmunge-generated files in removed list
    skip_prefixes = ("backups/", "data/", "compose.boxmunge")
    skip_exact = {"secrets.env"}
    for rel in sorted(current_files - incoming_files):
        if rel in skip_exact or any(rel.startswith(p) for p in skip_prefixes):
            continue
        removed.append(rel)

    return changed, added, removed


def run_diff(project_name: str, paths: BoxPaths, ref: str | None = None) -> int:
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists():
        print(f"ERROR: Project '{project_name}' not found.")
        return 1

    try:
        bundle_path = resolve_bundle_source(project_name, paths, ref=ref)
    except SourceError as e:
        print(f"ERROR: {e}")
        return 1

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            extracted = extract_bundle(bundle_path, Path(tmpdir))
        except ValueError as e:
            print(f"ERROR: {e}")
            return 1

        print(f"{project_name}: comparing current vs {bundle_path.name}")
        print()

        changed, added, removed = _compare_dirs(project_dir, extracted)

        if not changed and not added and not removed:
            print("  No changes detected — files are identical.")
            return 0

        for f in changed:
            print(f"  {f:<40} changed")
        for f in added:
            print(f"  {f:<40} added")
        for f in removed:
            print(f"  {f:<40} removed")

        print()

        # Check config changes
        try:
            manifest = load_manifest(extracted / "manifest.yml")
        except ManifestError:
            manifest = None

        if manifest:
            from boxmunge.caddy import generate_caddy_config
            from boxmunge.compose import generate_compose_override

            new_caddy = generate_caddy_config(manifest)
            current_caddy_path = paths.project_caddy_site(project_name)
            if current_caddy_path.exists():
                if new_caddy != current_caddy_path.read_text():
                    print("  Caddy config:     would change")
                else:
                    print("  Caddy config:     unchanged")
            else:
                print("  Caddy config:     would be created")

            new_compose = generate_compose_override(manifest)
            current_compose_path = paths.project_compose_override(project_name)
            if current_compose_path.exists():
                if new_compose != current_compose_path.read_text():
                    print("  Compose overlay:  would change")
                else:
                    print("  Compose overlay:  unchanged")
            else:
                print("  Compose overlay:  would be created")

        print()
        print(f"  Run 'stage {project_name}' to verify, or 'deploy {project_name}' to deploy directly.")

    return 0


def cmd_diff(args: list[str]) -> None:
    from boxmunge.paths import BoxPaths
    if not args:
        print("Usage: boxmunge diff <project> [--ref REF]", file=sys.stderr)
        sys.exit(2)
    project = args[0]
    ref = None
    remaining = args[1:]
    i = 0
    while i < len(remaining):
        if remaining[i] == "--ref" and i + 1 < len(remaining):
            ref = remaining[i + 1]
            i += 2
        else:
            i += 1
    paths = BoxPaths()
    sys.exit(run_diff(project, paths, ref=ref))
