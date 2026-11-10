# SPDX-License-Identifier: Apache-2.0
"""tests/spread_long.py: long tests spread through the first half of a run,
between files, without adding, dropping or splitting anything."""
from __future__ import annotations

from tests.spread_long import spread


def _items(files: int, per_file: int, long: int) -> list[str]:
    short = [f"f{f:02d}::t{t}" for f in range(files) for t in range(per_file)]
    return short[:per_file * files // 2] + [f"long::t{k}" for k in range(long)] + \
        short[per_file * files // 2:]


def _spread(items: list[str]) -> list[str]:
    return spread(items, lambda i: i.startswith("long::"), lambda i: i.split("::")[0])


def test_the_same_tests_in_a_new_order() -> None:
    items = _items(40, 5, 6)
    assert sorted(_spread(items)) == sorted(items)


def test_the_long_tests_are_apart_and_in_the_first_half() -> None:
    out = _spread(_items(40, 5, 6))
    at = [i for i, item in enumerate(out) if item.startswith("long::")]
    assert at[0] == 0
    assert all(b - a > 5 for a, b in zip(at, at[1:]))
    assert at[-1] < len(out) / 2
    assert [out[i] for i in at] == [f"long::t{k}" for k in range(6)]


def test_no_other_file_is_split() -> None:
    out = _spread(_items(40, 5, 6))
    files = [item.split("::")[0] for item in out if not item.startswith("long::")]
    runs = [f for i, f in enumerate(files) if i == 0 or f != files[i - 1]]
    assert len(runs) == len(set(runs))


def test_more_long_tests_than_files_still_keeps_every_test() -> None:
    items = _items(2, 3, 10)
    out = _spread(items)
    assert sorted(out) == sorted(items)


def test_nothing_long_or_nothing_else_is_left_alone() -> None:
    assert _spread(["a::1", "b::1"]) == ["a::1", "b::1"]
    assert _spread(["long::1", "long::2"]) == ["long::1", "long::2"]
