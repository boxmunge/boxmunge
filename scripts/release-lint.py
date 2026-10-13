#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Release class gate for .github/workflows/release.yml.

Two subcommands, both exit 1 with an ERROR: line on any violation:

  check  --tag vX.Y.Z --github-output FILE --notes-out FILE
         [--releases PATH] [--pyproject PATH]
      Before building: the tag must be vX.Y.Z, match pyproject.toml's version,
      and be listed in services/version-check/releases.json with a valid class
      (validated by the service's own release_catalog rules). Writes `class`
      and `title` to the GitHub step output file and the release-notes
      preamble to --notes-out. The class marker ([security] or [breakfix]) is
      generated from releases.json, so the notes cannot disagree with it.

  verify --release-json FILE --class CLASS
      After creating the draft release: FILE is `gh release view --json
      name,body`. Boxes that fall back to the GitHub API classify a release by
      the markers in its title and notes, so the draft must classify exactly as
      CLASS. This catches auto-generated notes that quote a PR title
      containing a marker.

Stdlib only, so it runs before any dependency is installed.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RELEASES_JSON = REPO / "services" / "version-check" / "releases.json"
PYPROJECT = REPO / "pyproject.toml"
CATALOG_MODULE = REPO / "services" / "version-check" / "release_catalog.py"
TAG_RE = re.compile(r"^v(\d+\.\d+\.\d+)$")

MARKERS = {"security": "[security]", "breakfix": "[breakfix]"}
PREAMBLE = {
    "security": ("[security] Security release. Every box on the {line} line applies it "
                 "automatically."),
    "breakfix": ("[breakfix] Break-fix release: a critical non-security fix. Boxes on the "
                 "{line} line apply it automatically unless boxmunge.yml sets "
                 "auto_update.breakfix: false."),
    "feature": ("Feature release. Boxes do not apply it automatically; operators run "
                "`upgrade` when ready."),
}


class ReleaseLintError(Exception):
    """The release must not be built or published."""


@dataclass(frozen=True)
class ReleasePlan:
    version: str
    release_class: str
    title: str
    notes: str


def _catalog():
    spec = importlib.util.spec_from_file_location("release_catalog", CATALOG_MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def classify_release(name: str, body: str) -> str:
    """The class a box infers from GitHub release text. Mirrors
    boxmunge.upgrade_discovery._github_release_class (tests cross-check)."""
    text = f"{name or ''}\n{body or ''}".lower()
    if MARKERS["security"] in text:
        return "security"
    if MARKERS["breakfix"] in text:
        return "breakfix"
    return "feature"


def plan_release(tag: str, releases_path: Path, pyproject_path: Path) -> ReleasePlan:
    match = TAG_RE.match(tag)
    if not match:
        raise ReleaseLintError(f"tag {tag!r} is not vX.Y.Z")
    version = match.group(1)
    declared = tomllib.loads(Path(pyproject_path).read_text())["project"]["version"]
    if declared != version:
        raise ReleaseLintError(
            f"tag {tag} does not match pyproject.toml version {declared}")
    catalog = _catalog()
    try:
        releases = catalog.load_releases(Path(releases_path))
    except catalog.ReleaseCatalogError as e:
        raise ReleaseLintError(str(e)) from e
    entry = next((r for r in releases if r["version"] == version), None)
    if entry is None:
        raise ReleaseLintError(
            f"{version} is not listed in {releases_path}; add it with its class "
            f"(feature, breakfix or security) before tagging")
    cls = entry["class"]
    line = ".".join(version.split(".")[:2])
    marker = MARKERS.get(cls)
    title = f"v{version} {marker}" if marker else f"v{version}"
    return ReleasePlan(version, cls, title, PREAMBLE[cls].format(line=line) + "\n")


def verify_release(name: str, body: str, expected: str) -> None:
    found = classify_release(name, body)
    if found != expected:
        raise ReleaseLintError(
            f"release text classifies as {found}, but releases.json says {expected}; "
            f"boxes using the GitHub fallback would treat it as {found}. "
            f"Edit the draft's title/notes so only the {expected} marker appears.")
    if expected in MARKERS and MARKERS[expected] not in (name or "").lower():
        raise ReleaseLintError(f"release title {name!r} lacks {MARKERS[expected]}")


def _cmd_check(args: argparse.Namespace) -> None:
    plan = plan_release(args.tag, Path(args.releases), Path(args.pyproject))
    Path(args.notes_out).write_text(plan.notes)
    with open(args.github_output, "a") as out:
        out.write(f"class={plan.release_class}\ntitle={plan.title}\n")
    print(f"{args.tag}: class {plan.release_class}, title {plan.title!r}")


def _cmd_verify(args: argparse.Namespace) -> None:
    view = json.loads(Path(args.release_json).read_text())
    verify_release(view.get("name") or "", view.get("body") or "", args.release_class)
    print(f"release text classifies as {args.release_class}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check")
    check.add_argument("--tag", required=True)
    check.add_argument("--releases", default=str(RELEASES_JSON))
    check.add_argument("--pyproject", default=str(PYPROJECT))
    check.add_argument("--github-output", required=True)
    check.add_argument("--notes-out", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--release-json", required=True)
    verify.add_argument("--class", dest="release_class", required=True,
                        choices=("feature", "breakfix", "security"))
    args = parser.parse_args(argv)
    try:
        {"check": _cmd_check, "verify": _cmd_verify}[args.command](args)
    except ReleaseLintError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
