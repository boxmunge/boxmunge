# SPDX-License-Identifier: Apache-2.0
"""tests/shard.py: CI's shards partition the test files, whole and balanced."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

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
        path, _, test = name.partition("::")
        assert (REPO / path).is_file(), f"{name} in {WEIGHTS.name} no longer exists"
        assert not test or f"def {test}(" in (REPO / path).read_text(), f"{name} is gone"
        assert isinstance(seconds, (int, float)) and seconds >= 0


# The two CI tiers that are sharded, as CI selects them.
TIERS = {
    "integration": ["tests/integration", "--ignore=tests/integration/userns",
                    "-m", "integration and not userns_dind"],
    "userns-dind": ["tests/integration/userns", "-m", "userns_dind"],
}


def _selected(tier: str, *args: str) -> list[str]:
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
         *TIERS[tier], *args],
        cwd=REPO, capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines() if "::" in line]


@pytest.mark.parametrize("tier", TIERS)
def test_the_shards_of_a_run_partition_its_tests(tier: str) -> None:
    everything = _selected(tier)
    shards = [_selected(tier, "--shard", f"{k}/3") for k in (1, 2, 3)]
    assert all(shards)
    assert sorted(t for shard in shards for t in shard) == sorted(everything)


def test_a_shard_by_test_module_is_split_and_every_other_kept_whole() -> None:
    shards = [_selected("userns-dind", "--shard", f"{k}/3") for k in (1, 2, 3)]
    homes: dict[str, set[int]] = {}
    for k, shard in enumerate(shards):
        for test in shard:
            homes.setdefault(test.split("::")[0], set()).add(k)
    split = {path for path, ks in homes.items() if len(ks) > 1}
    assert split == {"tests/integration/userns/test_migration_remapped.py"}


@pytest.mark.parametrize("job", ["integration", "userns-dind"])
def test_a_sharded_ci_job_runs_every_shard(job: str) -> None:
    """A shard missing from the matrix would drop its files without a word."""
    spec = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text())["jobs"][job]
    runs = " ".join(step.get("run", "") for step in spec["steps"])
    m = re.search(r"--shard \$\{\{ matrix\.shard \}\}/(\d+)\b", runs)
    assert m, f"{job} does not pass --shard K/N"
    n = int(m.group(1))
    assert spec["strategy"]["matrix"]["shard"] == list(range(1, n + 1))
    assert spec["strategy"]["fail-fast"] is False
    assert f"{{{{ matrix.shard }}}}/{n})" in spec["name"]
