# SPDX-License-Identifier: Apache-2.0
"""platform.info, status.get, projects.list, health.get and LiveHost."""
from __future__ import annotations

import json
import re

import pytest
import yaml

from boxmunge.api.dev.fixture_host import FixtureHost
from boxmunge.api.host import LiveHost
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.commands.handshake_cmd import run_handshake
from boxmunge.commands.health_cmd import HealthCheck, HealthReport
from boxmunge.docker import DockerError
from tests.api.fakes import make_invoker

WEBUI = Principal.plugin("webui", Tier.OBSERVE)


def _call(paths, name, params=None):
    invoker = make_invoker(paths, host=FixtureHost(paths))
    return invoker.invoke(name, params or {}, WEBUI).data


def test_platform_info(fixture_paths) -> None:
    info = _call(fixture_paths, "platform.info")
    handshake = run_handshake()
    assert info["api_version"] == "1.0"
    assert info["hostname"] == "box.example.test"
    assert info["server_version"] == handshake["server_version"]
    assert info["schema_version"] == handshake["schema_version"]


def test_platform_info_without_config_fails_with_the_reason(paths) -> None:
    with pytest.raises(ActionError) as excinfo:
        _call(paths, "platform.info")
    assert excinfo.value.code is ErrorCode.FAILED
    assert "Config file not found" in excinfo.value.message


TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z")


def test_status_get_returns_machine_values_not_display_labels(fixture_paths) -> None:
    rows = {r["project"]: r for r in _call(fixture_paths, "status.get")["projects"]}
    assert {name: row["status"] for name, row in rows.items()} == {
        "shop": "ok", "blog": "paused", "billing": "quarantined", "wiki": "failing",
        "newapp": "pre_registered"}
    assert rows["newapp"] == {"project": "newapp", "status": "pre_registered",
                              "last_check": None, "deployed_at": None,
                              "quarantine": None, "error": None}
    assert rows["billing"]["quarantine"]["cve_id"] == "CVE-2026-32003"
    assert TIMESTAMP_RE.fullmatch(rows["billing"]["quarantine"]["quarantined_at"])
    for row in rows.values():
        for key in ("last_check", "deployed_at"):
            assert row[key] is None or TIMESTAMP_RE.fullmatch(row[key]), (row, key)


def test_status_get_normalises_timestamps_to_utc_z(fixture_paths) -> None:
    path = fixture_paths.project_deploy_state("shop")
    record = json.loads(path.read_text())
    record["deployed_at"] = "2026-10-14T04:30:00+02:00"
    path.write_text(json.dumps(record))
    rows = {r["project"]: r for r in _call(fixture_paths, "status.get")["projects"]}
    assert rows["shop"]["deployed_at"] == "2026-10-14T02:30:00Z"


def test_a_stored_timestamp_that_is_not_one_is_an_error_row(fixture_paths) -> None:
    path = fixture_paths.project_deploy_state("shop")
    record = json.loads(path.read_text())
    record["deployed_at"] = "yesterday"
    path.write_text(json.dumps(record))
    rows = {r["project"]: r for r in _call(fixture_paths, "status.get")["projects"]}
    assert rows["shop"]["status"] == "error" and str(path) in rows["shop"]["error"]
    assert rows["blog"]["status"] == "paused"


def test_status_get_keeps_serving_with_one_corrupt_project(paths) -> None:
    for name in ("good", "bad"):
        (paths.projects / name).mkdir()
        (paths.projects / name / "manifest.yml").write_text(
            yaml.safe_dump({"schema_version": 3, "project": name}))
    paths.project_health_state("bad").write_text("{not json")
    rows = {r["project"]: r for r in _call(paths, "status.get")["projects"]}
    assert rows["bad"]["status"] == "error"
    assert "bad.json" in rows["bad"]["error"]
    assert rows["good"]["status"] == "unknown"


def test_projects_list(fixture_paths) -> None:
    assert _call(fixture_paths, "projects.list") == {
        "projects": ["billing", "blog", "newapp", "shop", "wiki"]}


def test_health_get_returns_the_host_report(fixture_paths) -> None:
    report = _call(fixture_paths, "health.get")
    assert report == FixtureHost(fixture_paths).health_report()
    assert report["exit_code"] == 1


def test_no_params_means_none(fixture_paths) -> None:
    with pytest.raises(ActionError) as excinfo:
        _call(fixture_paths, "status.get", {"verbose": True})
    assert excinfo.value.code is ErrorCode.INVALID_PARAMS


def test_live_host_health_uses_collect_health(paths, monkeypatch) -> None:
    report = HealthReport(checks=[HealthCheck("docker", "ok", "Docker daemon running")])
    monkeypatch.setattr("boxmunge.commands.health_cmd.collect_health", lambda p: report)
    assert LiveHost(paths).health_report() == report.to_dict()


def test_live_host_check_uses_collect_check(paths, monkeypatch) -> None:
    monkeypatch.setattr("boxmunge.commands.check.collect_check",
                        lambda project, p: {"project": project, "exit_code": 0, "status": "ok"})
    assert LiveHost(paths).project_check("shop")["project"] == "shop"


def test_live_host_logs_use_the_override_when_present(paths, monkeypatch) -> None:
    seen = {}

    def capture(project_dir, service=None, tail=100, compose_files=None, *, project_name):
        seen.update(service=service, tail=tail, files=compose_files, name=project_name)
        return "line\n"
    monkeypatch.setattr("boxmunge.docker.compose_logs_capture", capture)
    (paths.projects / "shop").mkdir()
    (paths.projects / "shop" / "compose.boxmunge.yml").write_text("services: {}\n")
    assert LiveHost(paths).container_logs("shop", "web", 7) == "line\n"
    assert seen == {"service": "web", "tail": 7, "name": "shop",
                    "files": ["compose.yml", "compose.boxmunge.yml"]}


def test_live_host_logs_raise_docker_errors(paths, monkeypatch) -> None:
    def fail(*args, **kwargs):
        raise DockerError("Cannot connect to the Docker daemon")
    monkeypatch.setattr("boxmunge.docker.compose_logs_capture", fail)
    (paths.projects / "shop").mkdir()
    with pytest.raises(DockerError):
        LiveHost(paths).container_logs("shop", None, 10)


def _rewrite_json(path, **changes):
    record = json.loads(path.read_text())
    for key, value in changes.items():
        if value is ...:
            del record[key]
        else:
            record[key] = value
    path.write_text(json.dumps(record))


@pytest.mark.parametrize("changes", [
    {"explanation": None}, {"severity": None}, {"effective_severity": 3},
    {"explanation": ...},
])
def test_a_quarantine_record_unlike_what_boxmunge_writes_is_an_error_row(
        fixture_paths, changes) -> None:
    """Writers always store these fields as text; a record that does not is
    corrupt, and must cost only its own row, not the whole dashboard."""
    path = fixture_paths.project_quarantine_state("billing")
    _rewrite_json(path, **changes)
    rows = {r["project"]: r for r in _call(fixture_paths, "status.get")["projects"]}
    assert rows["billing"]["status"] == "error"
    assert str(path) in rows["billing"]["error"]
    assert rows["shop"]["status"] == "ok"


def test_a_health_status_that_is_not_text_is_an_error_row(fixture_paths) -> None:
    path = fixture_paths.project_health_state("shop")
    _rewrite_json(path, status=None)
    rows = {r["project"]: r for r in _call(fixture_paths, "status.get")["projects"]}
    assert rows["shop"]["status"] == "error"
    assert str(path) in rows["shop"]["error"]


def test_quarantine_severity_is_a_lowercase_machine_value(fixture_paths) -> None:
    rows = {r["project"]: r for r in _call(fixture_paths, "status.get")["projects"]}
    assert rows["billing"]["quarantine"]["severity"] == "critical"
