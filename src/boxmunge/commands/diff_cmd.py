"""boxmunge diff <project> — preview what a deploy would change."""
from __future__ import annotations

import filecmp
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.bind_mounts import BindMountError, bind_mounted_dirs
from boxmunge.bundle import BundleError, check_bundle_contents, extract_bundle
from boxmunge.data_dirs import ReleaseStateError
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.release import check_install, project_data_dirs
from boxmunge.source import resolve_bundle_source, SourceError

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def _files(root: Path, skip: set[str]) -> set[str]:
    """Files under ``root`` as relative paths, outside its top-level ``skip`` entries."""
    files: set[str] = set()
    if not root.exists():
        return files
    for top in root.iterdir():
        if top.name in skip:
            continue
        for f in (top.rglob("*") if top.is_dir() and not top.is_symlink() else [top]):
            if f.is_file():
                files.add(str(f.relative_to(root)))
    return files


def _compare_dirs(current: Path, incoming: Path,
                  box_state: set[str]) -> tuple[list[str], list[str], list[str]]:
    """Compare two directories recursively, leaving out the ``box_state``
    entries: an install keeps the server's (secrets, data, the operator's
    caddy.override.conf, boxmunge's own files) and never installs a
    bundle's (release.install_release).
    Returns (changed, added, removed) as lists of relative path strings.
    """
    current_files = _files(current, box_state)
    incoming_files = _files(incoming, box_state)
    changed = [rel for rel in sorted(incoming_files & current_files)
               if not filecmp.cmp(current / rel, incoming / rel, shallow=False)]
    return changed, sorted(incoming_files - current_files), sorted(current_files - incoming_files)


def _is_git_project(project_name: str, paths: BoxPaths) -> bool:
    """Raises ManifestError when the project's manifest cannot be loaded."""
    return load_manifest(paths.project_manifest(project_name)).get("source") == "git"


def _bundle_manifest(extracted: Path, project_name: str) -> dict:
    """The bundle's manifest. Raises what a deploy refuses the bundle for
    first: no compose.yml (BundleError), and a manifest that cannot be read
    or names another project (ManifestError)."""
    if not (extracted / "compose.yml").is_file():
        raise BundleError("it has no compose.yml")
    manifest = load_manifest(extracted / "manifest.yml")
    named = manifest.get("project")
    if named != project_name:
        raise ManifestError(f"its manifest.yml names project {named!r}, not "
                            f"{project_name!r}")
    return manifest


def _refused(error: Exception, extracted: Path) -> int:
    # Name paths inside the bundle, not the temporary dir they were read from.
    print(f"ERROR: a deploy would refuse this bundle: "
          f"{str(error).replace(f'{extracted}/', '')}. Fix it and upload the "
          f"bundle again.", file=sys.stderr)
    return 1


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
        try:
            notes = check_bundle_contents(extracted)
            manifest = _bundle_manifest(extracted, project_name)
            bind_mounted_dirs(extracted / "compose.yml", project_dir)
        except (BundleError, ManifestError, BindMountError) as e:
            return _refused(e, extracted)

        print(f"{project_name}: comparing current vs {bundle_path.name}")
        for note in notes:
            print(f"  {note}")
        print()

        try:
            check_install(extracted, project_dir)
            box_state = project_data_dirs(project_dir, extracted).box_state()
        except BundleError as e:
            return _refused(e, extracted)
        except ReleaseStateError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        changed, added, removed = _compare_dirs(project_dir, extracted, box_state)

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

        from boxmunge.caddy import site_config
        from boxmunge.compose import (
            generate_compose_override, load_user_compose, recorded_users,
        )

        new_caddy, override = site_config(paths, project_name, manifest)
        source = f" (from {override.name})" if override is not None else ""
        current_caddy_path = paths.project_caddy_site(project_name)
        if current_caddy_path.exists():
            if new_caddy != current_caddy_path.read_text():
                print(f"  Caddy config:     would change{source}")
            else:
                print(f"  Caddy config:     unchanged{source}")
        else:
            print(f"  Caddy config:     would be created{source}")

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
