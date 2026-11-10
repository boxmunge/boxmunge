#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Release class gate for .github/workflows/release.yml.

Four subcommands, each exits 1 with an ERROR: line on any violation:

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

  notes  --preamble FILE --generated-json FILE --out FILE
      Before creating the draft: writes the release notes, the preamble from
      `check` followed by GitHub's generated changelog (FILE is the answer of
      the releases/generate-notes API). The changelog quotes PR titles, so
      every class marker in it is neutralised first ("[held]" becomes
      "(held)"): a contributor's PR title can neither reclassify a release
      for boxes on the GitHub fallback nor trip `verify`.

  verify --release-json FILE --class CLASS --breaking true|false
      After creating the draft release: FILE is `gh release view --json
      name,body`. Boxes that fall back to the GitHub API classify a release,
      and decide whether it is breaking, by the markers in its title and
      notes, so the draft must read exactly as CLASS and BREAKING: this
      catches a wrong title or preamble, and any marker `notes` missed.

  audit --github-releases FILE [--releases PATH] [--held X.Y.Z ...]
      Maintenance check, run by hand: FILE is
      `gh api --paginate --slurp 'repos/boxmunge/boxmunge/releases?per_page=100'`.
      Every release in releases.json must be published on GitHub with text
      that reads as its class and breaking flag, so GitHub-fallback boxes
      select exactly as the version-check service does, and exactly the
      --held versions (the ones the service's circuit breaker holds; none
      by default) must carry [held] in their title. Edit the title of any
      release it reports.

The [held] marker is the GitHub twin of a circuit-breaker hold, for boxes
that cannot reach the service. Boxes read it from the title only (notes
quote contributors' PR titles), so only someone with write access to the
repository can set it, and verify refuses a draft carrying it anywhere: a
release is published unheld, and held afterwards by editing its title.

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
HELD_MARKER = "[held]"
# Any marker as a box would read it (case-insensitively), in quoted text.
_QUOTED_MARKER = re.compile(r"\[(security|breakfix|breaking|held)\]", re.IGNORECASE)
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


def is_held(name: str) -> bool:
    """Whether a box reads a GitHub release as held: [held] in the title only.
    Mirrors boxmunge.release_selection.github_release_held (tests cross-check)."""
    return HELD_MARKER in (name or "").lower()


def neutralise_markers(text: str) -> str:
    """Quoted text with each class or hold marker turned into plain text:
    "[held] x" becomes "(held) x". Other brackets are left alone."""
    return _QUOTED_MARKER.sub(r"(\1)", text)


def compose_notes(preamble: str, changelog: str) -> str:
    """The release notes: the generated preamble, verbatim, then the
    changelog with its markers neutralised."""
    quoted = neutralise_markers(changelog)
    if (classify_release("", quoted) != "feature" or is_breaking("", quoted)
            or HELD_MARKER in quoted.lower()):
        raise ReleaseLintError(
            f"the changelog still reads as a marker after neutralising: {quoted!r}")
    return f"{preamble.rstrip()}\n\n{quoted}"


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
    if HELD_MARKER in f"{name or ''}\n{body or ''}".lower():
        raise ReleaseLintError(
            f"release text carries {HELD_MARKER}, but a release is published unheld: "
            f"remove it from the draft's title/notes. To hold a published release, trip "
            f"the circuit breaker and add {HELD_MARKER} to its title (docs/DEVELOPMENT.md).")
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


def audit_releases(releases_path: Path, github: list[dict],
                   held: set[str] = frozenset()) -> list[str]:
    """Raise listing every releases.json entry whose published GitHub release
    is missing or reads differently from its entry, or is held (or not)
    against `held`. Returns the tags held on GitHub."""
    catalog = _catalog()
    try:
        releases = catalog.load_releases(Path(releases_path))
    except catalog.ReleaseCatalogError as e:
        raise ReleaseLintError(str(e)) from e
    published = {r.get("tag_name"): r for r in github
                 if not r.get("draft") and not r.get("prerelease")}
    problems = [f"--held {v}: not a release listed in {releases_path}"
                for v in sorted(held - {entry["version"] for entry in releases})]
    held_tags = []
    for entry in releases:
        tag = f"v{entry['version']}"
        release = published.get(tag)
        if release is None:
            problems.append(f"{tag}: no published GitHub release")
            continue
        name, body = release.get("name") or "", release.get("body") or ""
        problems += _hold_problems(tag, name, body, entry["version"] in held)
        if is_held(name):
            held_tags.append(tag)
        found = classify_release(name, body)
        if found != entry["class"]:
            problems.append(f"{tag}: GitHub text reads as {found}, releases.json says "
                            f"{entry['class']}")
        if is_breaking(name, body) != entry["breaking"]:
            want = "add" if entry["breaking"] else "remove"
            problems.append(f"{tag}: GitHub text {'lacks' if entry['breaking'] else 'has'} "
                            f"{BREAKING_MARKER}, releases.json says breaking: "
                            f"{str(entry['breaking']).lower()} ({want} it)")
    if problems:
        raise ReleaseLintError(
            f"{len(problems)} release(s) on GitHub disagree with releases.json:\n  "
            + "\n  ".join(problems))
    return held_tags


def _hold_problems(tag: str, name: str, body: str, should_hold: bool) -> list[str]:
    problems = []
    if HELD_MARKER in body.lower() and not is_held(name):
        problems.append(f"{tag}: {HELD_MARKER} in its notes does nothing (boxes read it from "
                        f"the title only); move it to the title, or remove it")
    if should_hold and not is_held(name):
        problems.append(f"{tag}: held, but its GitHub title lacks {HELD_MARKER} (add it)")
    elif is_held(name) and not should_hold:
        problems.append(f"{tag}: its GitHub title carries {HELD_MARKER}, but --held does not "
                        f"name it (remove it, or pass --held {tag[1:]})")
    return problems


def _cmd_check(args: argparse.Namespace) -> None:
    plan = plan_release(args.tag, Path(args.releases), Path(args.pyproject))
    Path(args.notes_out).write_text(plan.notes)
    with open(args.github_output, "a") as out:
        out.write(f"class={plan.release_class}\n"
                  f"breaking={str(plan.breaking).lower()}\ntitle={plan.title}\n")
    print(f"{args.tag}: class {plan.release_class}, breaking {plan.breaking}, "
          f"title {plan.title!r}")


def _cmd_notes(args: argparse.Namespace) -> None:
    generated = json.loads(Path(args.generated_json).read_text())
    if not isinstance(generated, dict) or not isinstance(generated.get("body"), str):
        raise ReleaseLintError(
            f"{args.generated_json}: no release notes body in the generate-notes answer: "
            f"{json.dumps(generated)[:300]}")
    Path(args.out).write_text(compose_notes(Path(args.preamble).read_text(),
                                            generated["body"]))
    print(f"release notes written to {args.out}")


def _cmd_verify(args: argparse.Namespace) -> None:
    view = json.loads(Path(args.release_json).read_text())
    breaking = args.breaking == "true"
    verify_release(view.get("name") or "", view.get("body") or "", args.release_class,
                   breaking)
    print(f"release text classifies as {args.release_class}, breaking {breaking}")


def _cmd_audit(args: argparse.Namespace) -> None:
    github = json.loads(Path(args.github_releases).read_text())
    if not isinstance(github, list):
        raise ReleaseLintError(f"{args.github_releases}: expected a JSON list of releases")
    if github and all(isinstance(page, list) for page in github):
        github = [r for page in github for r in page]  # gh api --slurp pages
    if not all(isinstance(r, dict) for r in github):
        raise ReleaseLintError(f"{args.github_releases}: expected release objects")
    held = audit_releases(Path(args.releases), github, set(args.held))
    print(f"every release in {args.releases} reads the same on GitHub; "
          f"held on GitHub: {', '.join(held) or 'none'}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check")
    check.add_argument("--tag", required=True)
    check.add_argument("--releases", default=str(RELEASES_JSON))
    check.add_argument("--pyproject", default=str(PYPROJECT))
    check.add_argument("--github-output", required=True)
    check.add_argument("--notes-out", required=True)
    notes = sub.add_parser("notes")
    notes.add_argument("--preamble", required=True)
    notes.add_argument("--generated-json", required=True)
    notes.add_argument("--out", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--release-json", required=True)
    verify.add_argument("--class", dest="release_class", required=True,
                        choices=("feature", "breakfix", "security"))
    verify.add_argument("--breaking", required=True, choices=("true", "false"))
    audit = sub.add_parser("audit")
    audit.add_argument("--github-releases", required=True)
    audit.add_argument("--releases", default=str(RELEASES_JSON))
    audit.add_argument("--held", action="append", default=[], metavar="X.Y.Z",
                       help="a version the circuit breaker holds (repeat for each)")
    args = parser.parse_args(argv)
    try:
        {"check": _cmd_check, "notes": _cmd_notes, "verify": _cmd_verify,
         "audit": _cmd_audit}[args.command](args)
    except ReleaseLintError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
