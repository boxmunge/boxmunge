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
    skip_prefixes = ("backups/", "data/", "security/", ".releases/", "compose.boxmunge")
    skip_exact = {"secrets.env"}
    for rel in sorted(current_files - incoming_files):
        if rel in skip_exact or any(rel.startswith(p) for p in skip_prefixes):
            continue
        removed.append(rel)

    return changed, added, removed


def _is_git_project(project_name: str, paths: BoxPaths) -> bool:
    """Raises ManifestError when the project's manifest cannot be loaded."""
    return load_manifest(paths.project_manifest(project_name)).get("source") == "git"


def run_diff(project_name: str, paths: BoxPaths, ref: str | None = None) -> int:
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists():
        print(f"ERROR: Project '{project_name}' not found.", file=sys.stderr)
        return 1

    try:
        git = _is_git_project(project_name, paths)
    except ManifestError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    if git:
        print(f"ERROR: '{project_name}' is a git project, and diff compares inbox bundles "
              f"only. To preview what a ref would change, run: stage {project_name} "
              f"--ref <ref> --dry-run; or read the repository's history in "
              f"{project_dir / 'repo'}.", file=sys.stderr)
        return 1

    try:
        bundle_path = resolve_bundle_source(project_name, paths, ref=ref)
    except SourceError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            extracted = extract_bundle(bundle_path, Path(tmpdir))
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
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
            from boxmunge.compose import (
                generate_compose_override, load_user_compose, recorded_users,
            )

            new_caddy = generate_caddy_config(manifest)
            current_caddy_path = paths.project_caddy_site(project_name)
            if current_caddy_path.exists():
                if new_caddy != current_caddy_path.read_text():
                    print("  Caddy config:     would change")
                else:
                    print("  Caddy config:     unchanged")
            else:
                print("  Caddy config:     would be created")

            # v0.8: pass the candidate compose.yml from the new bundle so
            # the overlay omits read_only/tmpfs defaults consistently with
            # what a real deploy of this bundle would produce. The users are
            # those decided last: the deploy decides them again from its images.
            candidate_user_compose = load_user_compose(extracted / "compose.yml", project_name)
            new_compose = generate_compose_override(
                manifest, user_compose=candidate_user_compose,
                users=recorded_users(paths, project_name),
            )
            current_compose_path = paths.project_compose_override(project_name)
            if current_compose_path.exists():
                if new_compose != current_compose_path.read_text():
                    print("  Compose overlay:  would change")
                else:
                    print("  Compose overlay:  unchanged")
            else:
                print("  Compose overlay:  would be created")

        print()
        print(f"  Run 'stage {project_name}' to verify, or 'prod-deploy {project_name}' to deploy directly.")

    return 0


def cmd_diff(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name
    from boxmunge.paths import BoxPaths
    parsed = parse_args(
        "diff", args, options={"--ref"}, min_positional=1, max_positional=1,
    )
    project = require_project_name("diff", parsed.positional[0])
    paths = BoxPaths()
    sys.exit(run_diff(project, paths, ref=parsed.get("--ref")))
