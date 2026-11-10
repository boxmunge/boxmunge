#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail while a runtime lock has fallen behind.

The runtime locks (requirements.txt, requirements-tui.txt,
requirements-mcp.txt, cli/requirements.txt) are pyproject extras, which
Dependabot never regenerates: `make relock` refreshes them before each
release. A pin is overdue when a newer release in its major has been on PyPI
for more than MAX_AGE_DAYS: the 7-day cooldown `make relock` keeps
(.github/dependabot.yml) plus a week's grace. A new major is never overdue;
taking one is a decision of its own (relock-holds.txt). A calendar-versioned
package (a year for its major, as certifi's 2026.10.23) has no majors: a new
year is just its next release, so any newer release can be overdue.
CI runs this on release pull requests.

Usage: scripts/lock-freshness.py LOCK...
"""
from __future__ import annotations

import datetime as dt
import json
import re
import sys
import urllib.request
from typing import IO, Callable

from packaging.version import InvalidVersion, Version

MAX_AGE_DAYS = 14
# A major this large is a year: the package is calendar-versioned.
CALENDAR_MAJOR = 2000
# pydantic-core's full release history is about 13 MB of JSON.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
PIN_RE = re.compile(r"^([A-Za-z][\w.\-]*)(?:\[[^\]]*\])?==(\S+)", re.M)


class FetchError(Exception):
    """PyPI's release list for a package could not be read."""


def pins(text: str) -> dict[str, str]:
    """{package: pinned version} from a pip-compile lock."""
    return {m[1].lower(): m[2] for m in PIN_RE.finditer(text)}


def same_line(current: Version, version: Version) -> bool:
    """Whether `version` is a release the pin is expected to follow: its own
    major, or any release of a calendar-versioned package."""
    return current.major >= CALENDAR_MAJOR or version.major == current.major


def overdue(pinned: str, releases: dict[str, list[dict]], now: dt.datetime,
            max_age_days: int) -> str | None:
    """The newest release on the pin's line out longer than max_age_days and
    newer than the pin, or None. Pre-releases and fully yanked releases never count."""
    current = Version(pinned)
    best: Version | None = None
    for raw, files in releases.items():
        try:
            version = Version(raw)
        except InvalidVersion:
            continue
        live = [f for f in files if not f.get("yanked")]
        if (version.is_prerelease or version <= current or not live
                or not same_line(current, version)):
            continue
        uploaded = min(dt.datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00"))
                       for f in live)
        if (now - uploaded).days > max_age_days and (best is None or version > best):
            best = version
    return str(best) if best else None


def read_releases(stream: IO[bytes], name: str) -> dict[str, list[dict]]:
    """The `releases` map of a PyPI JSON response, refusing one past MAX_RESPONSE_BYTES."""
    body = stream.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise FetchError(f"{name}: PyPI's JSON is over {MAX_RESPONSE_BYTES // (1024 * 1024)} MiB; "
                         "refusing to read it (raise MAX_RESPONSE_BYTES if PyPI's answer is genuine)")
    try:
        return json.loads(body)["releases"]
    except (ValueError, KeyError, TypeError) as exc:
        raise FetchError(f"{name}: PyPI's answer is not a release list ({exc})") from exc


def fetch_pypi(name: str) -> dict[str, list[dict]]:
    url = f"https://pypi.org/pypi/{name}/json"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 (fixed https host)
            return read_releases(resp, name)
    except OSError as exc:  # URLError and timeouts included
        raise FetchError(f"{name}: could not fetch {url} ({exc}); re-run once PyPI answers") from exc


def main(argv: list[str], fetch: Callable[[str], dict] = fetch_pypi,
         now: dt.datetime | None = None) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    now = now or dt.datetime.now(dt.timezone.utc)
    stale = []
    for lock in argv:
        with open(lock, encoding="utf-8") as fh:
            for name, version in sorted(pins(fh.read()).items()):
                try:
                    newer = overdue(version, fetch(name), now, MAX_AGE_DAYS)
                except FetchError as exc:
                    print(f"ERROR: {lock}: {exc}", file=sys.stderr)
                    return 2
                if newer:
                    stale.append(f"  {lock}: {name} {version} (a newer {newer} is out "
                                 f"more than {MAX_AGE_DAYS} days)")
    if stale:
        print("ERROR: runtime locks have fallen behind; run `make relock` "
              "(docs/DEVELOPMENT.md) and commit the result:", *stale, sep="\n", file=sys.stderr)
        return 1
    print(f"Runtime locks current: no release older than {MAX_AGE_DAYS} days is missing "
          "(within each pin's major; calendar-versioned packages across years).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
