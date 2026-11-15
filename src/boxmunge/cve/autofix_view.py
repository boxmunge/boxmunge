# SPDX-License-Identifier: Apache-2.0
"""What `status`, `security <project>` and the API show of autofix.

Pure functions over what cve.autofix_record read: no I/O. A project with
patch records runs images that differ from its release ("patched"); one
with the marker is being patched now ("autofixing"). Times are ISO 8601
as the records hold them; the API reformats them (api.timefmt).
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

from boxmunge.cve.autofix_record import AutofixingMarker, PatchRecord


def patched_summary(records: Sequence[PatchRecord]) -> dict[str, Any] | None:
    """{since, cves, packages} over every record, or None with none: since
    the oldest patch, every CVE fixed and every package upgraded."""
    if not records:
        return None
    return {
        "since": min(r.created_at for r in records).isoformat(),
        "cves": sorted({cve for r in records for cve in r.cves}),
        "packages": sorted({p.name for r in records for p in r.packages}),
    }


def autofixing_summary(marker: AutofixingMarker | None) -> dict[str, Any] | None:
    """{started_at, cves, downtime} of a patch in progress, or None."""
    if marker is None:
        return None
    return {"started_at": marker.started_at.isoformat(), "cves": list(marker.cves),
            "downtime": marker.downtime}


def record_view(record: PatchRecord) -> dict[str, Any]:
    """One patch record in full."""
    return {
        "service": record.service, "base_ref": record.base_ref,
        "base_digest": record.base_digest, "patched_ref": record.patched_ref,
        "patched_image_id": record.patched_image_id,
        "packages": [{"name": p.name, "before": p.before, "after": p.after}
                     for p in record.packages],
        "cves": list(record.cves), "created_at": record.created_at.isoformat(),
        "trigger": record.trigger,
    }


def _utc(iso: str) -> datetime:
    return datetime.fromisoformat(iso).astimezone(timezone.utc)


def patched_line(summary: dict[str, Any]) -> str:
    """`status`'s line for a patched project."""
    n = len(summary["packages"])
    return (f"patched: running image differs from the release ({n} package"
            f"{'s' if n != 1 else ''} upgraded for {', '.join(summary['cves'])}, "
            f"since {_utc(summary['since']).date().isoformat()})")


def autofixing_line(summary: dict[str, Any]) -> str:
    """`status`'s line for a project being patched now."""
    site = "site down while it runs" if summary["downtime"] else "site up"
    started = _utc(summary["started_at"]).strftime("%Y-%m-%d %H:%M:%S")
    return f"autofixing: patching {', '.join(summary['cves'])} (started {started} UTC, {site})"


# A patched project's fix belongs in its repo: the next deploy is refused
# while its release brings a patched CVE back (the deploy guard).
BRING_INTO_REPO = ("bring the fix into the repo (bump the base image, or upgrade the "
                   "packages in the Dockerfile), then deploy")


def patch_lines(records: Sequence[PatchRecord], marker: AutofixingMarker | None) -> list[str]:
    """`security <project>`'s autofix block: a patch in progress, then every
    patch record in full."""
    lines: list[str] = []
    autofixing = autofixing_summary(marker)
    if autofixing is not None:
        lines += ["", f"  {autofixing_line(autofixing)}"]
    if not records:
        return lines
    lines += ["", f"  Patched by autofix ({len(records)} service"
                  f"{'s' if len(records) != 1 else ''}); the running images differ from "
                  f"the release:"]
    for r in records:
        lines += [
            f"    service: {r.service}",
            f"      fixed:        {', '.join(r.cves)}",
            *(f"      package:      {p.name} {p.before} -> {p.after}" for p in r.packages),
            f"      built from:   {r.base_ref} ({r.base_digest})",
            f"      runs:         {r.patched_ref} ({r.patched_image_id})",
            f"      patched at:   {r.created_at.isoformat()} ({r.trigger})",
        ]
    lines.append(f"    Next: {BRING_INTO_REPO}; until then the deploy guard refuses a "
                 f"release that brings a patched CVE back.")
    return lines
