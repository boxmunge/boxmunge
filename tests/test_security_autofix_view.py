"""`security <project>` lists every patch autofix applied, in full."""
from __future__ import annotations

import json

from boxmunge.commands.security_views import format_project_json, format_project_text
from boxmunge.cve.autofix_record import AutofixingMarker
from tests.autofix_helpers import PATCHED_AT, patch_record

MANIFEST = {"project": "shop", "schema_version": 3, "services": {
    "web": {"port": 8080}, "worker": {"internal": True}}}
VIEW = dict(posture="balanced", dangerously_disable_quarantine=False, quarantined=False,
            quarantine_state=None, scan_state=None, active_suppressions=(), users={})
RECORDS = (patch_record("shop", "web"), patch_record(
    "shop", "worker", cves=("CVE-2026-3",),
    packages=(("openssl", "3.0.1-1", "3.0.2-1"), ("zlib", "1.3-1", "1.3-2"))))


def test_security_project_lists_every_patch_record_in_full() -> None:
    text = format_project_text(MANIFEST, **VIEW, patches=RECORDS, autofixing=None)
    assert "Patched by autofix (2 services)" in text
    for line in ("service: web", "service: worker", "fixed:        CVE-2026-3",
                 "package:      zlib 1.3-1 -> 1.3-2",
                 "built from:   nginx:1.27 (sha256:" + "b" * 64 + ")",
                 "runs:         boxmunge.invalid/shop/worker:autofix-aaaaaaaaaaaa (sha256:",
                 "patched at:   2026-11-14T03:10:00+00:00 (urgent)",
                 "bring the fix into the repo"):
        assert line in text, line


def test_security_project_shows_a_patch_in_progress() -> None:
    marker = AutofixingMarker(PATCHED_AT, ("CVE-2026-4",), True)
    text = format_project_text(MANIFEST, **VIEW, patches=(), autofixing=marker)
    assert "autofixing: patching CVE-2026-4 (started 2026-11-14 03:10:00 UTC, " \
           "site down while it runs)" in text
    assert "Patched by autofix" not in text


def test_security_project_json_carries_the_records_and_the_marker() -> None:
    marker = AutofixingMarker(PATCHED_AT, ("CVE-2026-4",), False)
    cve = json.loads(format_project_json(MANIFEST, **VIEW, patches=RECORDS,
                                         autofixing=marker))["cve"]
    assert [p["service"] for p in cve["patches"]] == ["web", "worker"]
    assert cve["patches"][1]["packages"][1] == {"name": "zlib", "before": "1.3-1",
                                                "after": "1.3-2"}
    assert cve["autofixing"] == {"started_at": "2026-11-14T03:10:00+00:00",
                                 "cves": ["CVE-2026-4"], "downtime": False}
    unpatched = json.loads(format_project_json(MANIFEST, **VIEW, patches=(),
                                               autofixing=None))["cve"]
    assert unpatched["patches"] == [] and unpatched["autofixing"] is None
