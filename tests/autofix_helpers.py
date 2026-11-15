"""Patch records and an autofixing marker, written as autofix writes them."""
from __future__ import annotations

from datetime import datetime, timezone

from boxmunge.cve.autofix_record import (
    PackageChange, PatchRecord, mark_autofixing, write_records,
)
from boxmunge.paths import BoxPaths

PATCHED_AT = datetime(2026, 11, 14, 3, 10, tzinfo=timezone.utc)


def patch_record(project: str, service: str = "web", *, cves: tuple[str, ...] = ("CVE-2026-1",),
                 packages: tuple[tuple[str, str, str], ...] = (("openssl", "3.0.1-1", "3.0.2-1"),),
                 created_at: datetime = PATCHED_AT) -> PatchRecord:
    return PatchRecord(
        project=project, service=service, base_ref="nginx:1.27",
        base_digest="sha256:" + "b" * 64,
        patched_ref=f"boxmunge.invalid/{project}/{service}:autofix-{'a' * 12}",
        patched_image_id="sha256:" + "a" * 64,
        packages=tuple(PackageChange(*p) for p in packages), cves=cves,
        created_at=created_at, trigger="urgent")


def write_patches(paths: BoxPaths, project: str, *records: PatchRecord) -> None:
    write_records(paths, project, records or (patch_record(project),))


def mark_patching(paths: BoxPaths, project: str, cves: tuple[str, ...] = ("CVE-2026-2",),
                  *, downtime: bool = True) -> None:
    mark_autofixing(paths, project, cves, downtime=downtime)
