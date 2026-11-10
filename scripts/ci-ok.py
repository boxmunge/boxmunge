#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""CI's `ci-ok` job: pass only if every job it needs succeeded.

The one check main's ruleset requires, so the ruleset need not name each job
(the sharded matrix jobs' names carry their shard and daemon, and change with
them; `needs` reports each matrix as one job). Reads
the `needs` context as JSON from NEEDS and the event name from EVENT. A job
may be skipped only where its workflow skips it on purpose: dco runs on pull
requests only. Anything else, including cancelled, fails.

Usage: NEEDS='${{ toJSON(needs) }}' EVENT=... scripts/ci-ok.py
"""
from __future__ import annotations

import json
import os
import sys

# Jobs that legitimately skip, and the events they skip on.
SKIPS_ON = {"dco": {"push"}}


def failures(needs: dict, event: str) -> list[str]:
    bad = []
    for job, info in sorted(needs.items()):
        result = info["result"]
        if result == "success" or (result == "skipped" and event in SKIPS_ON.get(job, ())):
            continue
        bad.append(f"{job}: {result}")
    return bad


def main() -> int:
    needs = json.loads(os.environ["NEEDS"])
    event = os.environ["EVENT"]
    if not needs:
        print("ci-ok needs no jobs: its `needs:` list is empty", file=sys.stderr)
        return 1
    for job, info in sorted(needs.items()):
        print(f"{job}: {info['result']}")
    bad = failures(needs, event)
    if bad:
        print(f"Not every CI job passed ({event}): {', '.join(bad)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
