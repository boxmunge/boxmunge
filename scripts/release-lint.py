#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Release class gate for .github/workflows/release.yml.

Two subcommands, both exit 1 with an ERROR: line on any violation:

  check  --tag vX.Y.Z --github-output FILE --notes-out FILE
         [--releases PATH] [--pyproject PATH]
      Before building: the tag must be vX.Y.Z, match pyproject.toml's version,
      and be listed in services/version-check/releases.json with a valid class
      and `breaking` flag (validated by the service's own release_catalog
      rules). A breaking release must be X.Y.0: breaking changes bump the
      minor version. Writes `class`, `breaking` and `title` to the GitHub step
      output file and the release-notes preamble to --notes-out. The markers
      ([security] or [breakfix], and [breaking]) are generated from
      releases.json, so the notes cannot disagree with it.

  verify --release-json FILE --class CLASS --breaking true|false
      After creating the draft release: FILE is `gh release view --json
      name,body`. Boxes that fall back to the GitHub API classify a release,
      and decide whether it is breaking, by the markers in its title and
      notes, so the draft must read exactly as CLASS and BREAKING. This
      catches auto-generated notes that quote a PR title containing a marker.

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
BREAKING_MARKER = "[breaking]"
_REACH = ("Boxes on {major}.x apply it automatically when no breaking release (this one "
          "included) lies between their version and this one")
PREAMBLE = {
    "security": "[security] Security release. " + _REACH + ".",
    "breakfix": ("[breakfix] Break-fix release: a critical non-security fix. " + _REACH
                 + ", unless boxmunge.yml sets auto_update.breakfix: false."),
    "feature": ("Feature release. Boxes do not apply it automatically; operators run "
                "`upgrade` when ready."),
}
BREAKING_PREAMBLE = (
    "[breaking] Breaking release: it changes operator workflows or can make existing "
    "projects fail. Boxes never install it, or any later release across it, "
    "automatically. Read these notes, make the changes they describe, then run `upgrade`.")


class ReleaseLintError(Exception):
    """The release must not be built or published."""


@dataclass(frozen=True)
class ReleasePlan:
    version: str
    release_class: str
    breaking: bool
    title: str
    notes: str


def _catalog():
    spec = importlib.util.spec_from_file_location("release_catalog", CATALOG_MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def classify_release(name: str, body: str) -> str:
    """The class a box infers from GitHub release text. Mirrors
    boxmunge.release_selection.github_release_class (tests cross-check)."""
    text = f"{name or ''}\n{body or ''}".lower()
    if MARKERS["security"] in text:
        return "security"
    if MARKERS["breakfix"] in text:
        return "breakfix"
    return "feature"


def is_breaking(name: str, body: str) -> bool:
    """Whether a box reads GitHub release text as breaking. Mirrors
    boxmunge.release_selection.github_release_breaking (tests cross-check)."""
    return BREAKING_MARKER in f"{name or ''}\n{body or ''}".lower()


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
    cls, breaking = entry["class"], entry["breaking"]
    major, _minor, patch = version.split(".")
    if breaking and patch != "0":
        raise ReleaseLintError(
            f"{version} is marked breaking, but breaking changes bump the minor version; "
            f"release them as X.Y.0, or set \"breaking\": false if nothing breaks")
    markers = [m for m in (MARKERS.get(cls), BREAKING_MARKER if breaking else None) if m]
    title = " ".join([f"v{version}", *markers])
    notes = [PREAMBLE[cls].format(major=major)]
    if breaking:
        notes.append(BREAKING_PREAMBLE)
    return ReleasePlan(version, cls, breaking, title, "\n\n".join(notes) + "\n")


def verify_release(name: str, body: str, expected: str, expected_breaking: bool) -> None:
    found = classify_release(name, body)
    if found != expected:
        raise ReleaseLintError(
            f"release text classifies as {found}, but releases.json says {expected}; "
            f"boxes using the GitHub fallback would treat it as {found}. "
            f"Edit the draft's title/notes so only the {expected} marker appears.")
    if expected in MARKERS and MARKERS[expected] not in (name or "").lower():
        raise ReleaseLintError(f"release title {name!r} lacks {MARKERS[expected]}")
    found_breaking = is_breaking(name, body)
    if found_breaking != expected_breaking:
        state = "breaking" if found_breaking else "not breaking"
        fix = (f"put {BREAKING_MARKER} in the title" if expected_breaking
               else f"remove every {BREAKING_MARKER}")
        raise ReleaseLintError(
            f"release text reads as {state}, but releases.json says breaking: "
            f"{str(expected_breaking).lower()}; boxes using the GitHub fallback would "
            f"treat it as {state}. Edit the draft's title/notes to {fix}.")
    if expected_breaking and BREAKING_MARKER not in (name or "").lower():
        raise ReleaseLintError(f"release title {name!r} lacks {BREAKING_MARKER}")


def _cmd_check(args: argparse.Namespace) -> None:
    plan = plan_release(args.tag, Path(args.releases), Path(args.pyproject))
    Path(args.notes_out).write_text(plan.notes)
    with open(args.github_output, "a") as out:
        out.write(f"class={plan.release_class}\n"
                  f"breaking={str(plan.breaking).lower()}\ntitle={plan.title}\n")
    print(f"{args.tag}: class {plan.release_class}, breaking {plan.breaking}, "
          f"title {plan.title!r}")


def _cmd_verify(args: argparse.Namespace) -> None:
    view = json.loads(Path(args.release_json).read_text())
    breaking = args.breaking == "true"
    verify_release(view.get("name") or "", view.get("body") or "", args.release_class,
                   breaking)
    print(f"release text classifies as {args.release_class}, breaking {breaking}")


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
    verify.add_argument("--breaking", required=True, choices=("true", "false"))
    args = parser.parse_args(argv)
    try:
        {"check": _cmd_check, "verify": _cmd_verify}[args.command](args)
    except ReleaseLintError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
