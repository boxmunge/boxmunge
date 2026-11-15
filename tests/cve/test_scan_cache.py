# SPDX-License-Identifier: Apache-2.0
"""Trivy results kept by image ID and Trivy DB version (cve.scan_cache)."""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone

import pytest

from boxmunge.cve.scan_cache import CACHE_MAX_AGE, ScanCache
from boxmunge.cve.scanner import (
    AttackVector, Finding, PkgClass, ScanResult, Severity, VulnStatus,
)
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64


def _finding() -> Finding:
    return Finding(
        cve_id="CVE-2026-1111", severity=Severity.HIGH, package="openssl",
        installed_version="3.0.1", fixed_version="3.0.2", title="t", primary_url="https://x.test",
        attack_vector=AttackVector.NETWORK, status=VulnStatus.AFFECTED,
        vendor_severities={"debian": Severity.MEDIUM}, severity_source="debian",
        pkg_class=PkgClass.OS, cvss_score=7.5, pkg_type="debian")


def _result() -> ScanResult:
    return ScanResult("shop-web@" + DIGEST, (_finding(),), datetime.now(timezone.utc), "2:db-1",
                      frozenset({"python-pkg"}))


@pytest.fixture
def cache(tmp_path) -> ScanCache:
    return ScanCache(BoxPaths(root=tmp_path))


def test_a_result_reads_back_whole_for_the_same_db(cache) -> None:
    cache.put(DIGEST, "2:db-1", _result())
    got = cache.get(DIGEST, "2:db-1")
    assert got is not None
    assert got.findings == (_finding(),) and got.lang_types == frozenset({"python-pkg"})
    assert got.db_version == "2:db-1" and got.image_ref == DIGEST
    assert cache.get(OTHER, "2:db-1") is None


def test_cache_invalid_after_trivy_db_update(cache) -> None:
    cache.put(DIGEST, "2:db-1", _result())
    assert cache.get(DIGEST, "2:db-2") is None


def test_entries_live_under_state_scans_cache(cache, tmp_path) -> None:
    cache.put(DIGEST, "2:db-1", _result())
    assert (BoxPaths(root=tmp_path).scan_cache_dir / f"{'a' * 64}.json").is_file()


def test_a_malformed_entry_is_a_fault_naming_the_file(cache) -> None:
    cache.put(DIGEST, "2:db-1", _result())
    path = cache.dir / f"{'a' * 64}.json"
    doc = json.loads(path.read_text())
    del doc["findings"][0]["severity"]
    path.write_text(json.dumps(doc))
    with pytest.raises(StateError, match=str(path)):
        cache.get(DIGEST, "2:db-1")


def test_an_entry_for_another_digest_at_the_name_is_refused(cache) -> None:
    cache.put(DIGEST, "2:db-1", _result())
    path = cache.dir / f"{'a' * 64}.json"
    path.write_text(path.read_text().replace("a" * 64, "c" * 64))
    with pytest.raises(StateError, match="not sha256:aaa"):
        cache.get(DIGEST, "2:db-1")


def test_only_an_image_id_names_an_entry(cache) -> None:
    with pytest.raises(ValueError):
        cache.get("../../etc/passwd", "2:db-1")


def test_a_put_prunes_entries_older_than_fourteen_days(cache) -> None:
    cache.put(OTHER, "2:db-1", _result())
    old = cache.dir / f"{'b' * 64}.json"
    then = time.time() - CACHE_MAX_AGE.total_seconds() - 60
    os.utime(old, (then, then))
    cache.put(DIGEST, "2:db-1", _result())
    assert not old.exists() and cache.get(DIGEST, "2:db-1") is not None


def test_the_key_names_trivy_and_its_db_build(monkeypatch) -> None:
    import subprocess

    from boxmunge.cve import scanner
    out = json.dumps({"Version": "0.58.0", "VulnerabilityDB": {
        "Version": 2, "UpdatedAt": "2026-11-14T06:00:00Z", "NextUpdate": "x"}})
    monkeypatch.setattr(scanner.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(
        cmd, 0, out, ""))
    assert scanner.trivy_version_key() == "trivy 0.58.0, DB 2:2026-11-14T06:00:00Z"


def test_a_trivy_without_a_db_says_so(monkeypatch) -> None:
    import subprocess

    from boxmunge.cve import scanner
    monkeypatch.setattr(scanner.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(
        cmd, 0, json.dumps({"Version": "0.58.0"}), ""))
    with pytest.raises(scanner.ScannerError, match="vulnerability DB"):
        scanner.trivy_version_key()


def test_a_trivy_upgrade_invalidates_the_cache(cache) -> None:
    cache.put(DIGEST, "trivy 0.58.0, DB 2:db-1", _result())
    assert cache.get(DIGEST, "trivy 0.59.0, DB 2:db-1") is None
