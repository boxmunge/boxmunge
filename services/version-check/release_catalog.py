"""Release catalogue: load and validate releases.json, and decide what a caller is offered.

Every release has a class:

- ``feature``  — never auto-applied; the operator upgrades when ready.
- ``breakfix`` — a critical non-security fix; auto-applied by boxes that allow it
  (``auto_update.breakfix`` in boxmunge.yml, default on).
- ``security`` — always auto-applied. A security release is also a break-fix.

Every release also says whether it is ``breaking``: it changed an operator
workflow, or could make an existing project, manifest, compose file, command
line or upload method fail. Auto-update never installs across a breaking
release or into a new major version; the operator does that with ``upgrade``.

``/v1/check`` offers three candidates, each newer than the caller:

- ``security`` — newest reachable security release (the field deployed boxes read);
- ``breakfix`` — newest reachable breakfix-or-security release;
- ``latest``   — newest release of any class on any line.

A release is reachable from the caller when it has the caller's major
version and no release in (caller, release] is breaking. It may be on a
newer minor line. ``blocked`` names the newest security or break-fix release
that is not reachable, and why, so the box can alert its operator.

This module is pure (no Flask, no database) so the release lint
(scripts/release_lint.py) validates releases.json with exactly these rules.
"""

import json
import re
from pathlib import Path
from typing import Callable

RELEASE_CLASSES = ("feature", "breakfix", "security")
BREAKFIX_CLASSES = frozenset({"breakfix", "security"})
ENTRY_KEYS = frozenset({"version", "class", "breaking", "url"})
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
RELEASE_URL_PREFIX = "https://github.com/boxmunge/boxmunge/releases/tag/v"
HOLD_REASON = "circuit_breaker"


class ReleaseCatalogError(ValueError):
    """releases.json is malformed. The service refuses to start on this."""


# ---------------------------------------------------------------------------
# Loading and validation
# ---------------------------------------------------------------------------

def load_releases(path: Path) -> list[dict]:
    """Load releases.json and validate every entry. Raises ReleaseCatalogError."""
    try:
        data = json.loads(Path(path).read_text())
    except json.JSONDecodeError as e:
        raise ReleaseCatalogError(f"{path}: not valid JSON: {e}") from e
    validate_releases(data, source=str(path))
    return data["releases"]


def validate_releases(data: object, source: str) -> None:
    """Raise ReleaseCatalogError naming the first invalid entry."""
    if not isinstance(data, dict) or set(data) != {"releases"}:
        raise ReleaseCatalogError(f"{source}: top level must be an object with only 'releases'")
    releases = data["releases"]
    if not isinstance(releases, list) or not releases:
        raise ReleaseCatalogError(f"{source}: 'releases' must be a non-empty list")
    seen: set[str] = set()
    for index, entry in enumerate(releases):
        where = f"{source}: releases[{index}]"
        _validate_entry(entry, where)
        if entry["version"] in seen:
            raise ReleaseCatalogError(f"{where}: duplicate version {entry['version']}")
        seen.add(entry["version"])


def _validate_entry(entry: object, where: str) -> None:
    if not isinstance(entry, dict):
        raise ReleaseCatalogError(f"{where}: must be an object")
    keys = set(entry)
    if "security" in keys:
        raise ReleaseCatalogError(
            f"{where}: 'security' is no longer accepted; use "
            f"\"class\": one of {', '.join(RELEASE_CLASSES)}")
    missing = sorted(ENTRY_KEYS - keys)
    if missing:
        raise ReleaseCatalogError(f"{where}: missing {', '.join(missing)}")
    extra = sorted(keys - ENTRY_KEYS)
    if extra:
        raise ReleaseCatalogError(f"{where}: unknown key(s) {', '.join(extra)}")
    version = entry["version"]
    if not isinstance(version, str) or not VERSION_RE.match(version):
        raise ReleaseCatalogError(f"{where}: version {version!r} is not X.Y.Z")
    cls = entry["class"]
    if not isinstance(cls, str) or cls not in RELEASE_CLASSES:
        raise ReleaseCatalogError(
            f"{where}: class {cls!r} is not one of {', '.join(RELEASE_CLASSES)}")
    if not isinstance(entry["breaking"], bool):
        raise ReleaseCatalogError(
            f"{where}: breaking {entry['breaking']!r} must be true or false")
    expected_url = f"{RELEASE_URL_PREFIX}{version}"
    if entry["url"] != expected_url:
        raise ReleaseCatalogError(f"{where}: url must be {expected_url}")


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

def parse_version(v: str) -> tuple[int, ...] | None:
    """Parse a dotted numeric version to a tuple. Returns None if unparseable."""
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return None


def version_gt(a: str, b: str) -> bool:
    """True if version a > version b. False if either is unparseable."""
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        return False
    n = max(len(pa), len(pb))
    return pa + (0,) * (n - len(pa)) > pb + (0,) * (n - len(pb))


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------

def _newest(releases: list[dict], keep: Callable[[dict], bool]) -> dict | None:
    best = None
    for r in releases:
        if keep(r) and (best is None or version_gt(r["version"], best["version"])):
            best = r
    return best


def block_reason(releases: list[dict], caller: str, target: str) -> dict | None:
    """Why auto-update must not move ``caller`` to ``target``; None if it may.

    ``{"major": N}`` when ``target`` is in another major version, else
    ``{"breaking_release": V}`` naming the oldest breaking release in
    (caller, target], the target itself included.
    """
    pc, pt = parse_version(caller), parse_version(target)
    if pc is None or pt is None:
        raise ValueError(f"cannot compare versions {caller!r} and {target!r}")
    if pt[0] != pc[0]:
        return {"major": pt[0]}
    breaking = [r for r in releases
                if r["breaking"] and version_gt(r["version"], caller)
                and not version_gt(r["version"], target)]
    if not breaking:
        return None
    first = min(breaking, key=lambda r: parse_version(r["version"]))
    return {"breaking_release": first["version"]}


def select_offers(releases: list[dict], caller: str) -> dict[str, dict | None]:
    """Pick the security, breakfix and latest candidates for a caller version."""
    def reachable(r: dict) -> bool:
        return (version_gt(r["version"], caller)
                and block_reason(releases, caller, r["version"]) is None)

    latest = _newest(releases, lambda r: True)
    return {
        "security": _newest(
            releases, lambda r: r["class"] == "security" and reachable(r)),
        "breakfix": _newest(
            releases, lambda r: r["class"] in BREAKFIX_CLASSES and reachable(r)),
        "latest": latest if latest and version_gt(latest["version"], caller) else None,
    }


def find_blocked(releases: list[dict], caller: str) -> dict | None:
    """The newest security or break-fix release newer than ``caller`` that
    auto-update may not install, with the reason; None if there is none.

    Reachability only ever shrinks as versions rise (a breaking release or a
    major bump stays on the path of every later release), so when the newest
    such release is reachable, every older one is too.
    """
    newest = _newest(releases, lambda r: r["class"] in BREAKFIX_CLASSES
                     and version_gt(r["version"], caller))
    if newest is None:
        return None
    reason = block_reason(releases, caller, newest["version"])
    if reason is None:
        return None
    return {**_offer(newest), "reason": reason}


def apply_holds(
    offers: dict[str, dict | None], is_held: Callable[[str], bool],
) -> tuple[dict[str, dict | None], list[dict]]:
    """Withhold circuit-broken auto-apply candidates.

    A held candidate is withdrawn, not replaced by an older one, with one
    exception: when the breakfix candidate is held, the unheld security
    candidate stands in for it. A box that accepts break-fixes must never be
    offered less than a security-only box.

    Returns (offers, held) where held lists each withheld version once.
    """
    security, breakfix = offers["security"], offers["breakfix"]
    held_versions: list[str] = []
    if security and is_held(security["version"]):
        held_versions.append(security["version"])
        security = None
    if breakfix and (breakfix["version"] in held_versions or is_held(breakfix["version"])):
        if breakfix["version"] not in held_versions:
            held_versions.append(breakfix["version"])
        breakfix = security
    held = [{"version": v, "reason": HOLD_REASON} for v in held_versions]
    return {**offers, "security": security, "breakfix": breakfix}, held


def _offer(release: dict | None) -> dict | None:
    if release is None:
        return None
    return {"version": release["version"], "url": release["url"], "class": release["class"]}


def check_response(
    offers: dict[str, dict | None], held: list[dict], blocked: dict | None,
) -> dict:
    """Build the /v1/check response body."""
    if offers["security"]:
        status = "security_update_available"
    elif offers["breakfix"]:
        status = "breakfix_update_available"
    elif offers["latest"]:
        status = "update_available"
    else:
        status = "up_to_date"
    body = {
        "status": status,
        "security": _offer(offers["security"]),
        "breakfix": _offer(offers["breakfix"]),
        "latest": _offer(offers["latest"]),
        "blocked": blocked,
    }
    if held:
        body["held"] = held
    return body
