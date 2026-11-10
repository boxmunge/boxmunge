# SPDX-License-Identifier: Apache-2.0
"""Spread the tests marked `runs_long` through the first half of a run.

pytest-xdist hands each worker a run of consecutive tests. Left in collection
order, the long tests (the upgrade-shim shell scripts, tens of seconds each)
sit together, land on one or two workers, and the whole run waits for them.
Spread one at a time between the other tests' files, in the first half, each
starts early on a worker of its own and is done before the short tests are.

Only whole files of other tests are stepped over, so no file's module or
class fixtures are set up twice. Which tests run does not change: only the
order, and a serial run's order is still deterministic.
"""
from __future__ import annotations

import pytest


def spread(items: list, is_long, file_of) -> list:
    """`items` with the long ones moved to file boundaries of the others,
    evenly through the first half of the run, in their own order."""
    long = [item for item in items if is_long(item)]
    rest = [item for item in items if not is_long(item)]
    if not long or not rest:
        return items
    boundaries = [i for i in range(len(rest) + 1)
                  if i in (0, len(rest)) or file_of(rest[i]) != file_of(rest[i - 1])]
    step = len(rest) / 2 / len(long)
    out, done = [], 0
    for k, item in enumerate(long):
        at = next(b for b in boundaries if b >= max(done, k * step))
        out.extend(rest[done:at])
        done = at
        out.append(item)
    out.extend(rest[done:])
    return out


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    items[:] = spread(items, lambda item: item.get_closest_marker("runs_long") is not None,
                      lambda item: item.nodeid.split("::", 1)[0])
