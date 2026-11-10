# SPDX-License-Identifier: Apache-2.0
"""security.summary and security.project."""
from __future__ import annotations

import json

import pytest
import yaml

from boxmunge.api.dev.fixture_host import FixtureHost
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.cve.breaker import breaker_path
from boxmunge.manifest import CURRENT_SCHEMA_VERSION
from tests.api.fakes import make_invoker

WEBUI = Principal.plugin("webui", Tier.OBSERVE)


def _call(paths, name, params=None):
    return make_invoker(paths, host=FixtureHost(paths)).invoke(name, params or {}, WEBUI).data


def _error(paths, name, params) -> ActionError:
    with pytest.raises(ActionError) as excinfo:
        _call(paths, name, params)
    return excinfo.value


def test_summary_over_the_fixture(fixture_paths) -> None:
    summary = _call(fixture_paths, "security.summary")
    assert summary["projects_count"] == 5
    assert summary["posture_distribution"] == {
        "relaxed": 1, "balanced": 2, "strict": 1, "paranoid": 0}
    assert [q["project"] for q in summary["quarantined"]] == ["billing"]
    assert summary["held_by_breaker"] == {"projects": [], "error": None}


def test_summary_on_an_empty_box_keeps_its_shape(paths) -> None:
    summary = _call(paths, "security.summary")
    assert summary["projects_count"] == 0 and summary["quarantined"] == []


def test_breaker_held_projects_are_a_list(fixture_paths) -> None:
    path = breaker_path(fixture_paths)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"held": {"error": ["CVE-2026-1"], "shop": ["CVE-2026-2"]}}))
    held = _call(fixture_paths, "security.summary")["held_by_breaker"]
    assert held == {"projects": [{"project": "error", "cves": ["CVE-2026-1"]},
                                 {"project": "shop", "cves": ["CVE-2026-2"]}],
                    "error": None}


def test_corrupt_breaker_state_is_reported_not_hidden(fixture_paths) -> None:
    path = breaker_path(fixture_paths)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{")
    held = _call(fixture_paths, "security.summary")["held_by_breaker"]
    assert held["projects"] == [] and "cannot read" in held["error"]


def test_quarantined_project(fixture_paths) -> None:
    billing = _call(fixture_paths, "security.project", {"project": "billing"})
    assert billing["status"] == "quarantined"
    assert billing["quarantine"]["cve_id"] == "CVE-2026-32003"
    assert [(f["cve_id"], f["disposition"]) for f in billing["findings"]] == [
        ("CVE-2026-32003", "quarantine")]
    assert billing["findings"][0]["image_ref"].startswith("registry.example.test/billing@")


def test_clean_project_lists_every_finding(fixture_paths) -> None:
    shop = _call(fixture_paths, "security.project", {"project": "shop"})
    assert shop["status"] == "normal" and shop["quarantine"] is None
    assert [f["disposition"] for f in shop["findings"]] == ["informational", "ignored_fixed"]
    assert shop["posture"] == "balanced" and shop["off_services"] == []


def test_findings_from_older_scan_files_read_as_null(fixture_paths) -> None:
    path = fixture_paths.project_scan_state("shop")
    state = json.loads(path.read_text())
    for finding in state["decisions"][0]["findings"]:
        for key in ("kev_listed", "fix_would_quarantine", "pkg_class", "status"):
            finding.pop(key)
    path.write_text(json.dumps(state))
    finding = _call(fixture_paths, "security.project", {"project": "shop"})["findings"][0]
    assert finding["kev_listed"] is None and finding["pkg_class"] is None


def test_manifest_without_schema_version_reads_as_1(fixture_paths) -> None:
    path = fixture_paths.project_manifest("shop")
    manifest = yaml.safe_load(path.read_text())
    del manifest["schema_version"]
    path.write_text(yaml.safe_dump(manifest))
    before = _call(fixture_paths, "security.project", {"project": "shop"})
    path.write_text(yaml.safe_dump({**manifest, "schema_version": CURRENT_SCHEMA_VERSION}))
    assert before == _call(fixture_paths, "security.project", {"project": "shop"})


def test_pre_registered_project_has_no_security_view(fixture_paths) -> None:
    assert _error(fixture_paths, "security.project",
                  {"project": "newapp"}).code is ErrorCode.CONFLICT


def test_corrupt_scan_state_fails_naming_the_file(fixture_paths) -> None:
    path = fixture_paths.project_scan_state("shop")
    path.write_text("{not json")
    error = _error(fixture_paths, "security.project", {"project": "shop"})
    assert error.code is ErrorCode.FAILED and str(path) in error.message


def test_summary_lists_an_unreadable_project_and_keeps_serving(fixture_paths) -> None:
    path = fixture_paths.project_scan_state("shop")
    path.write_text("{not json")
    summary = _call(fixture_paths, "security.summary")
    assert summary["projects_count"] == 5
    assert [u["project"] for u in summary["unreadable"]] == ["shop"]
    assert str(path) in summary["unreadable"][0]["error"]
    assert sum(summary["posture_distribution"].values()) == 3  # newapp has no manifest


def _rewrite_json(path, **changes):
    record = json.loads(path.read_text())
    for key, value in changes.items():
        if value is ...:
            del record[key]
        else:
            record[key] = value
    path.write_text(json.dumps(record))


def test_a_quarantine_record_with_a_null_severity_fails_naming_the_file(fixture_paths) -> None:
    path = fixture_paths.project_quarantine_state("billing")
    _rewrite_json(path, severity=None)
    error = _error(fixture_paths, "security.project", {"project": "billing"})
    assert error.code is ErrorCode.FAILED and str(path) in error.message
    summary = _call(fixture_paths, "security.summary")
    assert [u["project"] for u in summary["unreadable"]] == ["billing"]


@pytest.mark.parametrize("field, value", [
    ("effective_severity", "Catastrophic"), ("base_severity", None), ("status", "maybe"),
])
def test_an_unrecognised_stored_value_is_refused_naming_file_and_field(
    fixture_paths, field, value,
) -> None:
    """Read as the platform reads it for enforcement: a corrupted value is an
    unreadable file, never "unknown"."""
    path = fixture_paths.project_scan_state("shop")
    state = json.loads(path.read_text())
    state["decisions"][0]["findings"][0][field] = value
    path.write_text(json.dumps(state))
    error = _error(fixture_paths, "security.project", {"project": "shop"})
    assert f"{path}: stored '{field}'" in error.message


def test_every_enum_reads_as_a_lowercase_machine_value(fixture_paths) -> None:
    path = fixture_paths.project_scan_state("shop")
    state = json.loads(path.read_text())
    finding = state["decisions"][0]["findings"][0]
    finding.update(base_severity="High", effective_severity="Critical",
                   attack_vector="Network", pkg_class="os-pkgs", status="will_not_fix")
    path.write_text(json.dumps(state))
    shown = _call(fixture_paths, "security.project", {"project": "shop"})["findings"][0]
    assert (shown["base_severity"], shown["effective_severity"], shown["attack_vector"],
            shown["pkg_class"], shown["status"]) == (
        "high", "critical", "network", "os", "will_not_fix")
    billing = _call(fixture_paths, "security.project", {"project": "billing"})["quarantine"]
    assert (billing["severity"], billing["effective_severity"]) == ("critical", "critical")
    summary = _call(fixture_paths, "security.summary")
    assert [q["severity"] for q in summary["quarantined"]] == ["critical"]


def test_summary_reports_where_the_kev_catalog_came_from(fixture_paths) -> None:
    fixture_paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    fixture_paths.kev_catalog.write_text(json.dumps({
        "source": "https://raw.githubusercontent.com/cisagov/kev-data/main/x.json",
        "released_at": "2026-01-06T19:44:45.179700+00:00",
        "fetched_at": "2026-01-07T00:00:00+00:00", "cve_ids": ["CVE-2026-1"]}))
    kev = _call(fixture_paths, "security.summary")["kev"]
    assert kev["source"] == "https://raw.githubusercontent.com/cisagov/kev-data/main/x.json"
    assert kev["released_at"] == "2026-01-06T19:44:45.179700Z"
    assert kev["fetched_at"] == "2026-01-07T00:00:00Z"
    assert kev["entries"] == 1
    assert "no KEV catalog has been accepted" in kev["stale_reason"]


def test_summary_without_a_kev_cache_says_so(paths) -> None:
    kev = _call(paths, "security.summary")["kev"]
    assert kev == {"source": None, "released_at": None, "fetched_at": None, "entries": 0,
                   "stale_reason": "no KEV catalog has been fetched yet"}
