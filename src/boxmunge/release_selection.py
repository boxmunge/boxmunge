# SPDX-License-Identifier: Apache-2.0
"""Which release auto-update may install — the GitHub-fallback twin of the
version-check service's selection (services/version-check/release_catalog.py).

The service cannot be imported here (it is deployed on its own), so the rule
is implemented twice; tests/test_release_selection_parity.py runs one
scenario table through both and fails if they ever disagree.

The rule: a security (or break-fix) candidate is the newest release of that
class newer than the box, with the box's major version, and with no breaking
release in (box, candidate], the candidate included. ``find_blocked`` names
the newest security or break-fix release that rule excludes, and why.

On GitHub a release's class and breaking flag come from markers in its title
or notes: ``[security]``, ``[breakfix]`` and ``[breaking]``. The release
workflow generates them from releases.json and verifies the published text
carries exactly those (scripts/release-lint.py).

A circuit-breaker hold has a GitHub twin too: ``[held]`` in a release's
*title* (never its notes, which quote contributors' PR titles). Only someone
with write access to the repository can edit a release title, and the
release workflow never publishes one with the marker, so it is the
maintainer's deliberate edit, made when tripping the breaker. ``withhold``
applies it exactly as the service applies its holds.
"""
from __future__ import annotations

import re
from typing import Any, Callable

GITHUB_REPO = "boxmunge/boxmunge"
RELEASE_PAGE_PREFIX = f"https://github.com/{GITHUB_REPO}/releases/"
RELEASE_CLASSES = ("feature", "breakfix", "security")
AUTO_CLASSES = frozenset({"breakfix", "security"})
MODES = ("security", "breakfix", "latest")
# Which release classes each discovery mode accepts.
MODE_CLASSES = {
    "security": frozenset({"security"}),
    "breakfix": AUTO_CLASSES,
    "latest": frozenset(RELEASE_CLASSES),
}
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_TAG_RE = re.compile(r"^v(\d+\.\d+\.\d+)$")


def version_tuple(v: str) -> tuple[int, ...] | None:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return None


def newer(candidate: str, current: str) -> bool:
    """True if candidate > current. False if either is unparseable."""
    c, cur = version_tuple(candidate), version_tuple(current)
    if c is None or cur is None:
        return False
    n = max(len(c), len(cur))
    return c + (0,) * (n - len(c)) > cur + (0,) * (n - len(cur))


def _text(release: dict[str, Any]) -> str:
    return f"{release.get('name') or ''}\n{release.get('body') or ''}".lower()


def github_release_class(release: dict[str, Any]) -> str:
    text = _text(release)
    if "[security]" in text:
        return "security"
    if "[breakfix]" in text:
        return "breakfix"
    return "feature"


def github_release_breaking(release: dict[str, Any]) -> bool:
    return "[breaking]" in _text(release)


HELD_MARKER = "[held]"
GITHUB_HOLD_REASON = "github_held_marker"


def github_release_held(release: dict[str, Any]) -> bool:
    """True if the release title (only the title) carries ``[held]``."""
    return HELD_MARKER in (release.get("name") or "").lower()


def parse_github_releases(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Published vX.Y.Z server releases from the GitHub releases API, as
    {version, url, class, breaking, held}. Drafts, prereleases, client tags
    (cli-v*) and releases whose page is not in this repository are dropped."""
    releases = []
    for r in raw:
        if r.get("draft") or r.get("prerelease"):
            continue
        match = _TAG_RE.match(r.get("tag_name") or "")
        url = r.get("html_url") or ""
        if not match or not url.startswith(RELEASE_PAGE_PREFIX):
            continue
        releases.append({"version": match.group(1), "url": url,
                         "class": github_release_class(r),
                         "breaking": github_release_breaking(r),
                         "held": github_release_held(r)})
    return releases


def _newest(releases: list[dict[str, Any]],
            keep: Callable[[dict[str, Any]], bool]) -> dict[str, Any] | None:
    best = None
    for r in releases:
        if keep(r) and (best is None or newer(r["version"], best["version"])):
            best = r
    return best


def block_reason(releases: list[dict[str, Any]], current: str,
                 target: str) -> dict[str, Any] | None:
    """Why auto-update must not move ``current`` to ``target``; None if it may.

    ``{"major": N}`` when ``target`` is in another major version, else
    ``{"breaking_release": V}`` naming the oldest breaking release in
    (current, target], the target itself included.
    """
    pc, pt = version_tuple(current), version_tuple(target)
    if pc is None or pt is None:
        raise ValueError(f"cannot compare versions {current!r} and {target!r}")
    if pt[0] != pc[0]:
        return {"major": pt[0]}
    on_path = [r for r in releases
               if r["breaking"] and newer(r["version"], current)
               and not newer(r["version"], target)]
    if not on_path:
        return None
    first = min(on_path, key=lambda r: version_tuple(r["version"]))
    return {"breaking_release": first["version"]}


def select(releases: list[dict[str, Any]], current: str,
           mode: str) -> dict[str, Any] | None:
    """The release ``mode`` would install: {version, url, class} or None.

    ``latest`` is the newest release of any class (manual upgrade). The auto
    modes take only releases auto-update may reach.
    """
    classes = MODE_CLASSES[mode]

    def keep(r: dict[str, Any]) -> bool:
        if r["class"] not in classes or not newer(r["version"], current):
            return False
        return mode == "latest" or block_reason(releases, current, r["version"]) is None

    best = _newest(releases, keep)
    if best is None:
        return None
    return {"version": best["version"], "url": best["url"], "class": best["class"]}


def find_blocked(releases: list[dict[str, Any]], current: str) -> dict[str, Any] | None:
    """The newest security or break-fix release newer than ``current`` that
    auto-update may not install, as {version, url, class, reason}; else None.

    Reachability only shrinks as versions rise, so when the newest such
    release is reachable, every older one is too.
    """
    newest = _newest(releases, lambda r: r["class"] in AUTO_CLASSES
                     and newer(r["version"], current))
    if newest is None:
        return None
    reason = block_reason(releases, current, newest["version"])
    if reason is None:
        return None
    return {"version": newest["version"], "url": newest["url"],
            "class": newest["class"], "reason": reason}


def withhold(offers: dict[str, dict[str, Any] | None],
             is_held: Callable[[str], bool]) -> tuple[dict[str, dict[str, Any] | None], list[str]]:
    """The service's apply_holds, for the GitHub fallback.

    A held security or break-fix candidate is withdrawn, not replaced by an
    older one, except that an unheld security candidate stands in for a held
    break-fix candidate. ``latest`` is left as it is (the box skips a held
    one; see upgrade_discovery). Returns (offers, held versions, each once).
    """
    security, breakfix = offers["security"], offers["breakfix"]
    held: list[str] = []
    if security and is_held(security["version"]):
        held.append(security["version"])
        security = None
    if breakfix and (breakfix["version"] in held or is_held(breakfix["version"])):
        if breakfix["version"] not in held:
            held.append(breakfix["version"])
        breakfix = security
    return {**offers, "security": security, "breakfix": breakfix}, held


def github_check_response(releases: list[dict[str, Any]], current: str) -> dict[str, Any]:
    """What the version-check service's /v1/check would answer, built from
    the GitHub releases list (parse_github_releases), ``[held]`` titles as
    the holds."""
    marked = {r["version"] for r in releases if r["held"]}
    offers, held = withhold({mode: select(releases, current, mode) for mode in MODES},
                            marked.__contains__)
    return {**offers, "blocked": find_blocked(releases, current),
            "held": [{"version": v, "reason": GITHUB_HOLD_REASON} for v in held]}
