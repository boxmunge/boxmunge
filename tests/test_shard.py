# SPDX-License-Identifier: Apache-2.0
"""tests/shard.py: CI's shards partition the test files, whole and balanced."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.shard import WEIGHTS, assign, parse_shard

REPO = Path(__file__).resolve().parent.parent


def test_every_file_lands_in_exactly_one_shard() -> None:
    files = [f"tests/t{i}.py" for i in range(17)]
    shards = assign(files, {"tests/t3.py": 90.0, "tests/t4.py": 5.0}, 4)
    placed = [f for shard in shards for f in shard]
    assert sorted(placed) == sorted(files)


def test_heavy_files_spread_and_light_ones_fill_in() -> None:
    weights = {"a": 100.0, "b": 90.0, "c": 50.0, "d": 40.0, "e": 10.0}
    shards = assign(list(weights), weights, 2)
    loads = sorted(sum(weights[f] for f in s) for s in shards)
    assert loads == [140.0, 150.0]


def test_an_unmeasured_file_weighs_the_mean_of_the_measured() -> None:
    shards = assign(["a", "b", "new"], {"a": 30.0, "b": 10.0}, 2)
    assert shards == [["a"], ["new", "b"]]


def test_the_assignment_does_not_depend_on_collection_order() -> None:
    files = [f"f{i}" for i in range(9)]
    assert assign(files, {}, 3) == assign(list(reversed(files)), {}, 3)


@pytest.mark.parametrize("spec", ["0/3", "4/3", "1", "a/b", "1/2/3"])
def test_a_bad_shard_spec_is_a_usage_error(spec: str) -> None:
    with pytest.raises(pytest.UsageError):
        parse_shard(spec)


def test_the_committed_weights_are_seconds_per_existing_file() -> None:
    weights = json.loads(WEIGHTS.read_text())
    assert weights
    for name, seconds in weights.items():
        assert (REPO / name).is_file(), f"{name} in {WEIGHTS.name} no longer exists"
        assert isinstance(seconds, (int, float)) and seconds >= 0


def _selected(*args: str) -> set[str]:
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
         "tests/integration", "--ignore=tests/integration/userns", "-m", "integration", *args],
        cwd=REPO, capture_output=True, text=True, check=True).stdout
    return {line for line in out.splitlines() if "::" in line}


def test_the_shards_of_a_run_partition_its_tests() -> None:
    everything = _selected()
    shards = [_selected("--shard", f"{k}/3") for k in (1, 2, 3)]
    assert all(shards)
    assert set().union(*shards) == everything
    assert sum(len(s) for s in shards) == len(everything)

