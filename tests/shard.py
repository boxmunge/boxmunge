# SPDX-License-Identifier: Apache-2.0
"""Split a test run into shards of whole files, for CI's parallel jobs.

`--shard K/N` runs shard K (1-based) of N. Every test file goes to exactly
one shard, whole, so module-scoped fixtures (a built image, a remapped
daemon) are set up once, as in an unsharded run. Files are balanced by the
seconds each took in a measured run (tests/shard_weights.json, written by
`--store-shard-weights`, or taken from the per-file seconds a sharded run
prints last); a file not measured yet weighs the mean of those that were.
Stale weights only unbalance the shards: they never drop a test.

The split happens after `-m` and `-k` selection, over the files that still
hold a test, so every shard of the same command line sees the same files and
the shards partition them.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

WEIGHTS = Path(__file__).parent / "shard_weights.json"


def parse_shard(spec: str) -> tuple[int, int]:
    """'K/N' as (K, N), with 1 <= K <= N."""
    try:
        k, n = (int(part) for part in spec.split("/"))
    except ValueError:
        raise pytest.UsageError(f"--shard takes K/N, e.g. 2/3, not {spec!r}") from None
    if not 1 <= k <= n:
        raise pytest.UsageError(f"--shard {spec}: K must be between 1 and N")
    return k, n


def assign(files: list[str], weights: dict[str, float], shards: int) -> list[list[str]]:
    """Files into `shards` lists, heaviest file first onto the lightest shard.

    Deterministic: ties break by file name and shard number, so every shard
    job computes the same assignment."""
    known = [weights[f] for f in files if f in weights]
    default = sum(known) / len(known) if known else 1.0
    load = [0.0] * shards
    out: list[list[str]] = [[] for _ in range(shards)]
    for f in sorted(files, key=lambda f: (-weights.get(f, default), f)):
        lightest = min(range(shards), key=lambda i: (load[i], i))
        out[lightest].append(f)
        load[lightest] += weights.get(f, default)
    return out


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("shard")
    group.addoption("--shard", metavar="K/N",
                    help="run only shard K of N: whole test files, balanced by "
                         "tests/shard_weights.json")
    group.addoption("--store-shard-weights", metavar="PATH",
                    help="write each test file's total seconds to PATH (JSON), "
                         "merged over what PATH already holds")


def _file_of(nodeid: str) -> str:
    return nodeid.split("::", 1)[0]


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    spec = config.getoption("--shard")
    if not spec:
        return
    k, n = parse_shard(spec)
    weights = json.loads(WEIGHTS.read_text())
    files = sorted({_file_of(item.nodeid) for item in items})
    mine = set(assign(files, weights, n)[k - 1])
    keep = [item for item in items if _file_of(item.nodeid) in mine]
    dropped = [item for item in items if _file_of(item.nodeid) not in mine]
    if dropped:
        config.hook.pytest_deselected(items=dropped)
    items[:] = keep


class _WeightRecorder:
    """Each file's seconds: written to `path` (merged), or printed after a
    sharded run, so a CI log holds the numbers to refresh the weights."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.seconds: dict[str, float] = defaultdict(float)

    def _rounded(self) -> dict[str, float]:
        return {f: round(s, 1) for f, s in sorted(self.seconds.items())}

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        self.seconds[_file_of(report.nodeid)] += report.duration

    def pytest_sessionfinish(self) -> None:
        if self.path is None:
            return
        merged = json.loads(self.path.read_text()) if self.path.exists() else {}
        merged.update(self._rounded())
        self.path.write_text(json.dumps(dict(sorted(merged.items())), indent=1) + "\n")

    def pytest_terminal_summary(self, terminalreporter) -> None:
        if self.path is None:
            terminalreporter.write_line(
                f"shard weights (seconds per file): {json.dumps(self._rounded())}")


def pytest_configure(config: pytest.Config) -> None:
    path = config.getoption("--store-shard-weights")
    # Under xdist only the controller records: it sees every worker's reports.
    if (path or config.getoption("--shard")) and not hasattr(config, "workerinput"):
        config.pluginmanager.register(_WeightRecorder(Path(path) if path else None),
                                      "shard-weights")
