# SPDX-License-Identifier: Apache-2.0
"""platform.info, status.get, projects.list, health.get and LiveHost."""
from __future__ import annotations

import pytest
import yaml

from boxmunge.api.dev.fixture_host import FixtureHost
from boxmunge.api.host import LiveHost
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.commands.handshake_cmd import run_handshake
from boxmunge.commands.health_cmd import HealthCheck, HealthReport
from boxmunge.commands.status import collect_status
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


def test_status_get_returns_the_status_json_rows(fixture_paths) -> None:
    assert _call(fixture_paths, "status.get") == {
        "projects": collect_status(fixture_paths).rows}


def test_status_get_keeps_serving_with_one_corrupt_project(paths) -> None:
    for name in ("good", "bad"):
        (paths.projects / name).mkdir()
        (paths.projects / name / "manifest.yml").write_text(
            yaml.safe_dump({"schema_version": 3, "project": name}))
    paths.project_health_state("bad").write_text("{not json")
    rows = {r["project"]: r for r in _call(paths, "status.get")["projects"]}
    assert rows["bad"]["raw_status"] == "error"
    assert "bad.json" in rows["bad"]["error"]
    assert rows["good"]["raw_status"] == "unknown"


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
