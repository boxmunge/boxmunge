#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail while a runtime lock has fallen behind.

The runtime locks (requirements.txt, requirements-tui.txt,
requirements-mcp.txt, cli/requirements.txt) are pyproject extras, which
Dependabot never regenerates: `make relock` refreshes them before each
release. A pin is overdue when a newer release in its major has been on PyPI
for more than MAX_AGE_DAYS: the 7-day cooldown `make relock` keeps
(.github/dependabot.yml) plus a week's grace. A new major is never overdue;
taking one is a decision of its own (RELOCK_HOLDS in the Makefile).
CI runs this on release pull requests.

Usage: scripts/lock-freshness.py LOCK...
"""
from __future__ import annotations

import datetime as dt
import json
import re
import sys
import urllib.request
from typing import Callable

from packaging.version import InvalidVersion, Version

MAX_AGE_DAYS = 14
PIN_RE = re.compile(r"^([A-Za-z][\w.\-]*)(?:\[[^\]]*\])?==(\S+)", re.M)


def pins(text: str) -> dict[str, str]:
    """{package: pinned version} from a pip-compile lock."""
    return {m[1].lower(): m[2] for m in PIN_RE.finditer(text)}


def overdue(pinned: str, releases: dict[str, list[dict]], now: dt.datetime,
            max_age_days: int) -> str | None:
    """The newest same-major release out longer than max_age_days and newer
    than the pin, or None. Pre-releases and fully yanked releases never count."""
    current = Version(pinned)
    best: Version | None = None
    for raw, files in releases.items():
        try:
            version = Version(raw)
        except InvalidVersion:
            continue
        live = [f for f in files if not f.get("yanked")]
        if (version.is_prerelease or version <= current or not live
                or version.major != current.major):
            continue
        uploaded = min(dt.datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00"))
                       for f in live)
        if (now - uploaded).days > max_age_days and (best is None or version > best):
            best = version
    return str(best) if best else None


def fetch_pypi(name: str) -> dict[str, list[dict]]:
    url = f"https://pypi.org/pypi/{name}/json"
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 (fixed https host)
        return json.load(resp)["releases"]


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
                newer = overdue(version, fetch(name), now, MAX_AGE_DAYS)
                if newer:
                    stale.append(f"  {lock}: {name} {version} (a newer {newer} is out "
                                 f"more than {MAX_AGE_DAYS} days)")
    if stale:
        print("ERROR: runtime locks have fallen behind; run `make relock` "
              "(docs/DEVELOPMENT.md) and commit the result:", *stale, sep="\n", file=sys.stderr)
        return 1
    print(f"Runtime locks current: no same-major release older than {MAX_AGE_DAYS} days is missing.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
