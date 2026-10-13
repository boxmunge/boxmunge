# SPDX-License-Identifier: Apache-2.0
"""The fleet blast-radius circuit breaker's pure decision."""
from __future__ import annotations

import pytest

from boxmunge.cve.breaker import (
    BreakerError,
    Candidate,
    decide,
    read_held,
    trip_threshold,
    write_held,
)
from boxmunge.paths import BoxPaths


def _c(*cves: str, kev: bool = False) -> Candidate:
    return Candidate(cves=frozenset(cves), kev=kev)


@pytest.mark.parametrize("scanned, threshold", [(1, 2), (2, 2), (3, 2), (5, 2), (6, 3),
                                                (10, 4), (30, 11)])
def test_threshold_is_max_2_or_a_third(scanned, threshold):
    assert trip_threshold(scanned) == threshold


def test_single_project_box_never_trips():
    v = decide({"a": _c("CVE-1")}, projects_scanned=1, already_held={})
    assert v.apply == {"a"} and not v.tripped


def test_shared_cve_across_the_threshold_is_held():
    cands = {p: _c("CVE-1") for p in ("a", "b", "c")}
    v = decide(cands, projects_scanned=3, already_held={})
    assert v.tripped and v.apply == frozenset()
    assert set(v.held) == {"a", "b", "c"} and v.newly_held == {"a", "b", "c"}


def test_below_threshold_applies():
    cands = {"a": _c("CVE-1"), "b": _c("CVE-1"), "c": _c("CVE-1")}
    v = decide(cands, projects_scanned=10, already_held={})  # threshold 4
    assert not v.tripped and v.apply == {"a", "b", "c"}


def test_run_total_of_distinct_cves_trips():
    """A poisoned DB surfaces many different CVEs at once."""
    cands = {p: _c(f"CVE-{i}") for i, p in enumerate("abcd")}
    v = decide(cands, projects_scanned=10, already_held={})
    assert v.tripped and set(v.held) == set("abcd")


def test_kev_is_never_held_and_does_not_count():
    cands = {p: _c("CVE-K", kev=True) for p in "abcdef"}
    cands["g"] = _c("CVE-1")
    v = decide(cands, projects_scanned=7, already_held={})
    assert not v.tripped and v.apply == set("abcdefg")


def test_kev_applies_while_non_kev_is_held():
    cands = {"a": _c("CVE-1"), "b": _c("CVE-1"), "k": _c("CVE-K", "CVE-1", kev=True)}
    v = decide(cands, projects_scanned=3, already_held={})
    assert v.apply == {"k"} and set(v.held) == {"a", "b"}


def test_already_held_cve_stays_held_even_alone():
    """A per-project scan (N=1) cannot trip, but must not release a hold."""
    v = decide({"a": _c("CVE-1")}, projects_scanned=1,
               already_held={"a": frozenset({"CVE-1"}), "b": frozenset({"CVE-1"})})
    assert v.apply == frozenset() and v.held == {"a": frozenset({"CVE-1"})}
    assert v.newly_held == frozenset()


def test_a_new_unheld_cve_is_not_hidden_by_a_hold():
    v = decide({"a": _c("CVE-1", "CVE-2")}, projects_scanned=1,
               already_held={"b": frozenset({"CVE-1"})})
    assert v.apply == {"a"}


def test_held_state_round_trips_and_empties(tmp_path):
    paths = BoxPaths(root=tmp_path)
    paths.state.mkdir(parents=True)
    write_held(paths, {"a": frozenset({"CVE-2", "CVE-1"})})
    assert read_held(paths) == {"a": frozenset({"CVE-1", "CVE-2"})}
    write_held(paths, {})
    assert read_held(paths) == {}


def test_corrupt_held_state_fails_loudly(tmp_path):
    paths = BoxPaths(root=tmp_path)
    paths.state.mkdir(parents=True)
    (paths.state / "cve-breaker.json").write_text("{broken")
    with pytest.raises(BreakerError):
        read_held(paths)
