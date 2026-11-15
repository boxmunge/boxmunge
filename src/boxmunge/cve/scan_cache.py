# SPDX-License-Identifier: Apache-2.0
"""Trivy results kept by image ID, so an unchanged image is not scanned again.

The deploy guard scans every image a release would start, on every stage,
deploy, promote and rollback (commands/security_regression_guard), and a
quarantined project's gate scans them again (commands/quarantine_gate). An
image ID (``sha256:<hex>``) names exactly one image, so what Trivy found in
it stays true until Trivy or its vulnerability DB changes: each entry
records both (scanner.trivy_version_key) and is used only with the same.
Policy is never cached: the findings are judged afresh each time, against
today's known-exploited lists.

Entries live at ``state/scans/cache/<hex>.json``:
``{"digest": "sha256:<hex>", "trivy": str, "scanned_at": ISO8601,
"lang_types": [str], "findings": [{every Finding field}]}``. An entry not
rewritten for CACHE_MAX_AGE is pruned whenever one is written. The directory
is deploy-writable, so it is read without following links, and an entry that
cannot be read is a fault (StateError), never a miss. Code running as
deploy could still plant an entry; every use of one is printed and logged
(cached_results), and TRUST_MODEL.md says what the guard protects against.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from boxmunge.cve.scan_state import stored_enum
from boxmunge.cve.scanner import (
    AttackVector, Finding, PkgClass, ScanResult, Severity, VulnStatus,
)
from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import read_text_nofollow_or_none
from boxmunge.log import log_operation, log_warning
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

CACHE_MAX_AGE = timedelta(days=14)
_DIGEST = re.compile(r"sha256:([0-9a-f]{64})")


def _finding_doc(f: Finding) -> dict[str, Any]:
    return {
        "cve_id": f.cve_id, "severity": f.severity.value, "package": f.package,
        "installed_version": f.installed_version, "fixed_version": f.fixed_version,
        "title": f.title, "primary_url": f.primary_url,
        "attack_vector": f.attack_vector.value if f.attack_vector else None,
        "status": f.status.value,
        "vendor_severities": {k: v.value for k, v in f.vendor_severities.items()},
        "severity_source": f.severity_source, "pkg_class": f.pkg_class.value,
        "cvss_score": f.cvss_score, "pkg_type": f.pkg_type,
    }


def _finding(raw: dict[str, Any]) -> Finding:
    vendor = raw["vendor_severities"]
    if not isinstance(vendor, dict):
        raise TypeError("vendor_severities is not an object")
    score = raw["cvss_score"]
    if score is not None and (isinstance(score, bool) or not isinstance(score, (int, float))):
        raise TypeError(f"cvss_score {score!r} is not a number")
    return Finding(
        cve_id=str(raw["cve_id"]), severity=stored_enum(Severity, raw["severity"], "severity"),
        package=str(raw["package"]), installed_version=str(raw["installed_version"]),
        fixed_version=raw["fixed_version"], title=str(raw["title"]),
        primary_url=raw["primary_url"],
        attack_vector=None if raw["attack_vector"] is None else stored_enum(
            AttackVector, raw["attack_vector"], "attack_vector"),
        status=stored_enum(VulnStatus, raw["status"], "status"),
        vendor_severities={k: stored_enum(Severity, v, f"vendor_severities[{k}]")
                           for k, v in vendor.items()},
        severity_source=raw["severity_source"],
        pkg_class=stored_enum(PkgClass, raw["pkg_class"], "pkg_class"),
        cvss_score=None if score is None else float(score), pkg_type=raw["pkg_type"],
    )


class ScanCache:
    def __init__(self, paths: BoxPaths) -> None:
        self.dir = paths.scan_cache_dir

    def _path(self, digest: str) -> Path:
        match = _DIGEST.fullmatch(digest)
        if match is None:
            raise ValueError(f"{digest!r} is not an image ID (sha256:<64 hex>)")
        return self.dir / f"{match.group(1)}.json"

    def get(self, digest: str, trivy_key: str) -> ScanResult | None:
        """What Trivy found in the image ``digest`` with this Trivy and DB,
        or None when nothing was kept for it with them. Raises StateError."""
        path = self._path(digest)
        raw = read_text_nofollow_or_none(path)
        if raw is None:
            return None
        try:
            doc = json.loads(raw)
            if not isinstance(doc, dict):
                raise TypeError("not a JSON object")
            if doc["digest"] != digest:
                raise ValueError(f"it is for {doc['digest']!r}, not {digest}")
            if doc["trivy"] != trivy_key:
                return None
            if not isinstance(doc["findings"], list) or not isinstance(doc["lang_types"], list):
                raise TypeError("findings and lang_types must be lists")
            findings = tuple(_finding(f) for f in doc["findings"])
            lang_types = frozenset(str(t) for t in doc["lang_types"])
            scanned_at = datetime.fromisoformat(doc["scanned_at"])
        except (ValueError, KeyError, TypeError, StateError) as e:
            raise StateError(f"{path}: unreadable scan cache entry ({e}); delete it and the "
                             f"next scan writes it again") from e
        return ScanResult(digest, findings, scanned_at, trivy_key, lang_types)

    def put(self, digest: str, trivy_key: str, result: ScanResult) -> None:
        """Keep ``result`` for the image ``digest`` and this Trivy and DB,
        then prune entries older than CACHE_MAX_AGE. Raises OSError."""
        path = self._path(digest)
        atomic_write_text(path, json.dumps({
            "digest": digest, "trivy": trivy_key,
            "scanned_at": result.scanned_at.isoformat(),
            "lang_types": sorted(result.lang_types),
            "findings": [_finding_doc(f) for f in result.findings],
        }) + "\n")
        self._prune(keep=path.name)

    def _prune(self, keep: str) -> None:
        cutoff = time.time() - CACHE_MAX_AGE.total_seconds()
        with os.scandir(self.dir) as entries:
            for entry in entries:
                if (entry.name != keep and entry.name.endswith(".json")
                        and entry.is_file(follow_symlinks=False)
                        and entry.stat(follow_symlinks=False).st_mtime < cutoff):
                    os.unlink(entry.path)


def cached_results(paths: BoxPaths, project: str, digests: dict[str, str],
                   trivy_key: str) -> dict[str, ScanResult]:
    """{ref: its kept result} of the images in ``digests`` ({ref: image ID})
    kept for this Trivy and DB. Each use is printed and logged: the cache is
    deploy-writable. Raises StateError or OSError."""
    cache = ScanCache(paths)
    known: dict[str, ScanResult] = {}
    for ref, digest in digests.items():
        hit = cache.get(digest, trivy_key)
        if hit is not None:
            known[ref] = replace(hit, image_ref=ref)
            message = f"using cached scan of {ref} from {hit.scanned_at.isoformat()}"
            print(f"  {message} ({trivy_key}).")
            log_operation("cve-scan", message, paths, project=project,
                          detail={"image_id": digest, "trivy": trivy_key})
    return known


def keep_results(paths: BoxPaths, project: str, digests: dict[str, str], trivy_key: str,
                 results: dict[str, ScanResult]) -> None:
    """Keep each new result. One that cannot be kept is warned: the scan
    stands, and the next one scans the image again."""
    cache = ScanCache(paths)
    for ref, result in sorted(results.items()):
        try:
            cache.put(digests[ref], trivy_key, result)
        except OSError as e:
            print(f"  WARNING: keeping the scan of {ref} failed: {e}")
            log_warning("cve-scan", f"keeping the scan of {ref} failed: {e}", paths,
                        project=project)
