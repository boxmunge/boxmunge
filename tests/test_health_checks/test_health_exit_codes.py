# SPDX-License-Identifier: Apache-2.0
"""`health` exit 2 during an upgrade's probation rolls the platform back and
blocklists the release; a traceback exits 1, which the shim reads as healthy.
So a broken per-project input is a warning naming the project, the cause and
the fix, a probe that times out is a warning naming the command, and the rest
of the report always completes."""
from __future__ import annotations

import functools
import json
import subprocess
import sys

import pytest
import yaml

from boxmunge import compose_inventory
from boxmunge.commands import health_cmd
from boxmunge.commands.health_cmd import HealthCheck, run_guarded, run_health
from boxmunge.health_checks import hardening, sshd, userns
from boxmunge.health_checks.projects import check_project_containers
from boxmunge.paths import BoxPaths

LEGACY = "site-staging"
# The real listing; the autouse fake_containers fixture replaces it per test.
REAL_INVENTORY = compose_inventory.running_inventory


def _ok(name: str):
    return lambda *a, **k: HealthCheck(name, "ok", "stubbed")


@pytest.fixture
def platform_ok(monkeypatch):
    """The platform-level checks pass, so only per-project inputs can fail."""
    for module, attr, name in (
        (health_cmd, "check_docker_running", "docker"),
        (health_cmd, "check_caddy_container", "caddy"),
        (health_cmd, "check_system_container", "system-container"),
        (health_cmd, "check_age_key", "age-key"),
        (sshd, "check_sshd_hardening", "sshd-hardening"),
        (sshd, "check_sshd_deploy_env", "sshd-deploy-env"),
        (userns, "check_docker_userns", "docker-userns"),
        (hardening, "check_ufw", "ufw"),
    ):
        monkeypatch.setattr(module, attr, _ok(name))


def _project(paths: BoxPaths, dirname: str, manifest: dict | str) -> None:
    d = paths.projects / dirname
    d.mkdir(parents=True, exist_ok=True)
    text = manifest if isinstance(manifest, str) else yaml.safe_dump(manifest)
    (d / "manifest.yml").write_text(text)


def _manifest(name: str) -> dict:
    return {"schema_version": 3, "id": "01TEST", "project": name, "source": "bundle",
            "hosts": [f"{name}.example.com"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}}}


@pytest.fixture
def broken_box(paths: BoxPaths) -> BoxPaths:
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text("hostname: box.example.com\nadmin_email: a@b.c\n")
    _project(paths, "aaa", _manifest("aaa"))
    _project(paths, LEGACY, _manifest(LEGACY))                  # #122
    _project(paths, "tornq", _manifest("tornq"))
    paths.project_quarantine_state("tornq").parent.mkdir(parents=True, exist_ok=True)
    paths.project_quarantine_state("tornq").write_text("{")      # torn quarantine marker
    _project(paths, "tornp", _manifest("tornp"))
    paths.project_paused_state("tornp").parent.mkdir(parents=True, exist_ok=True)
    paths.project_paused_state("tornp").write_text("{")          # torn pause marker
    _project(paths, "badyaml", "project: [\n")                   # unparseable manifest
    (paths.projects / "nodir").mkdir(parents=True)
    (paths.projects / "nodir" / "manifest.yml").mkdir()          # unreadable manifest
    _project(paths, "badname", {**_manifest("x"), "project": "../x"})
    nohosts = {k: v for k, v in _manifest("nohosts").items() if k != "hosts"}
    _project(paths, "nohosts", nohosts)                          # cannot generate its config
    paths.project_caddy_site("nohosts").parent.mkdir(parents=True, exist_ok=True)
    paths.project_caddy_site("nohosts").write_text("old\n")
    return paths


BROKEN = (LEGACY, "tornq", "tornp", "badyaml", "nodir", "badname", "nohosts")


@pytest.mark.usefixtures("docker_down", "platform_ok")
def test_broken_project_inputs_warn_and_the_report_completes(broken_box, capsys):
    rc = run_health(broken_box, as_json=True)
    report = json.loads(capsys.readouterr().out)
    checks = {c["name"]: c for c in report["checks"]}
    assert rc <= 1, [c for c in report["checks"] if c["status"] == "error"]
    assert not [c for c in report["checks"] if c["status"] == "error"]
    assert "timers" in checks and "recent-errors" in checks  # ran to the end
    warned = " ".join(c["detail"] for c in report["checks"] if c["status"] == "warn")
    for name in BROKEN:
        assert name in warned, name
    lifecycle = checks["lifecycle"]["detail"]
    assert "Choose a name without the suffix" in lifecycle and "recreate it" in lifecycle
    assert "tornq" in lifecycle and "restore it from a backup" in lifecycle
    assert "tornp" in lifecycle
    drift = checks["config-drift"]["detail"]
    assert "`validate badyaml`" in drift and "nodir" in drift
    assert "badname: its project field '../x' does not match" in drift
    assert "nohosts: cannot generate its Caddy config: 'hosts' must contain" in drift


def test_project_containers_timeout_is_a_warning_naming_the_command(paths, monkeypatch):
    """One `docker ps` lists every project's containers, so it is the command named."""
    _project(paths, "myapp", _manifest("myapp"))

    def timeout(cmd, **_):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=10)

    monkeypatch.setattr(compose_inventory, "running_inventory", REAL_INVENTORY)
    monkeypatch.setattr(subprocess, "run", timeout)
    check = check_project_containers(paths)
    assert check.status == "warn"
    assert "did not answer within 10s" in check.detail
    assert "`docker ps --filter label=com.docker.compose.project" in check.detail


def _raise_timeout(cmd, *a, **k):
    raise subprocess.TimeoutExpired(cmd=cmd, timeout=k.get("timeout", 10))


def test_sshd_deploy_env_timeout_is_a_warning_naming_sshd(monkeypatch, paths):
    monkeypatch.setattr(sshd.os, "geteuid", lambda: 0)
    check = run_guarded("sshd-deploy-env", lambda: sshd.check_sshd_deploy_env(run=_raise_timeout),
                        paths)
    assert check.status == "warn"
    assert "/usr/sbin/sshd -T" in check.detail and "30s" in check.detail


def test_every_probe_timing_out_is_warnings_not_critical(paths, monkeypatch, capsys):
    """A busy host where every command times out: no traceback, no exit 2."""
    monkeypatch.setattr(health_cmd, "check_age_key", _ok("age-key"))
    monkeypatch.setattr(sshd, "check_sshd_hardening", _ok("sshd-hardening"))
    monkeypatch.setattr(subprocess, "run", _raise_timeout)
    monkeypatch.setattr(sshd, "check_sshd_deploy_env",
                        functools.partial(sshd.check_sshd_deploy_env, run=_raise_timeout))
    monkeypatch.setattr("os.geteuid", lambda: 0)   # ufw and sshd -T probe as root
    rc = run_health(paths, as_json=True)
    checks = {c["name"]: c for c in json.loads(capsys.readouterr().out)["checks"]}
    assert rc == 1, {n: c for n, c in checks.items() if c["status"] == "error"}
    for name, command in (("docker", "docker info"), ("caddy", "docker inspect"),
                          ("system-container", "docker inspect"), ("ufw", "ufw status"),
                          ("sshd-deploy-env", "sshd -T")):
        assert checks[name]["status"] == "warn", checks[name]
        assert command in checks[name]["detail"], checks[name]


def test_a_check_that_raises_unexpectedly_warns_and_is_logged(paths):
    def boom():
        raise KeyError("decisions")

    check = run_guarded("cve-hardening", boom, paths)
    assert check.status == "warn"
    assert "KeyError" in check.detail and "decisions" in check.detail
    assert "cve-hardening" in paths.log_file.read_text()


def test_permission_error_as_non_root_is_a_skip(paths, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)

    def denied():
        raise PermissionError(13, "Permission denied", "/var/lib/aide")

    check = run_guarded("aide", denied, paths)
    assert check.status == "skip" and "needs root" in check.detail


def test_ufw_probe_failure_is_a_warning_and_inactive_stays_critical(monkeypatch):
    monkeypatch.setattr(hardening.os, "geteuid", lambda: 0)
    monkeypatch.setattr(hardening, "_run", lambda args, timeout: subprocess.CompletedProcess(
        args, 1, "", "ERROR: problem running iptables: Another app is holding the xtables lock"))
    check = hardening.check_ufw()
    assert check.status == "warn" and "xtables lock" in check.detail
    monkeypatch.setattr(hardening, "_run", lambda args, timeout: subprocess.CompletedProcess(
        args, 0, "Status: inactive\n", ""))
    assert hardening.check_ufw().status == "error"


def test_system_container_inspect_timeout_is_a_warning(paths, monkeypatch):
    from boxmunge import system_container
    monkeypatch.setattr(system_container.subprocess, "run", _raise_timeout)
    check = health_cmd.check_system_container(paths)
    assert check.status == "warn" and "timed out" in check.detail


def test_a_generate_failure_on_a_valid_manifest_is_not_blamed_on_it(paths, monkeypatch):
    """Only validation decides it is the manifest's fault; else run_guarded sees it."""
    from boxmunge import caddy
    from boxmunge.health_checks.projects import check_config_drift
    _project(paths, "aaa", _manifest("aaa"))
    paths.project_caddy_site("aaa").parent.mkdir(parents=True, exist_ok=True)
    paths.project_caddy_site("aaa").write_text("old\n")

    def broken(manifest):
        raise KeyError("upstream")

    monkeypatch.setattr(caddy, "generate_caddy_config", broken)
    with pytest.raises(KeyError):
        check_config_drift(paths)
    check = run_guarded("config-drift", lambda: check_config_drift(paths), paths)
    assert check.status == "warn" and "KeyError" in check.detail


# ---- a defect in this release's own code rolls back: exit 2 ----

@pytest.mark.parametrize("exc,named", [
    (ModuleNotFoundError("No module named 'boxmunge.gone'", name="boxmunge.gone"),
     "cannot import boxmunge.gone"),
    (NameError("name 'helper' is not defined", name="helper"), "'helper' is not defined"),
    (SyntaxError("invalid syntax", ("boxmunge/x.py", 3, 1, "x")), "boxmunge/x.py:3"),
    (AttributeError("module 'boxmunge.notify' has no attribute 'gone'", name="gone",
                    obj=sys.modules["boxmunge.log"]), "boxmunge.log has no attribute 'gone'"),
])
def test_a_code_defect_is_an_error_naming_what_is_broken(paths, exc, named):
    def check():
        raise exc

    result = run_guarded("alerts", check, paths)
    assert result.status == "error" and named in result.detail
    assert "this boxmunge release is broken" in paths.log_file.read_text()


@pytest.mark.parametrize("exc", [KeyError("decisions"), TypeError("bad"),
                                 AttributeError("'list' object has no attribute 'get'")])
def test_a_data_driven_exception_still_warns(paths, exc):
    def check():
        raise exc

    assert run_guarded("cve-hardening", check, paths).status == "warn"


@pytest.mark.parametrize("broken", ["boxmunge.health_checks.alerts", "boxmunge.notify"],
                         ids=["check-module", "module-it-imports"])
@pytest.mark.usefixtures("docker_down", "platform_ok")
def test_an_unimportable_module_fails_its_check_with_exit_2(paths, monkeypatch, capsys, broken):
    monkeypatch.delitem(sys.modules, "boxmunge.health_checks.alerts", raising=False)
    monkeypatch.setitem(sys.modules, broken, None)   # import of it raises ImportError
    rc = run_health(paths, as_json=True)
    checks = {c["name"]: c for c in json.loads(capsys.readouterr().out)["checks"]}
    assert rc == 2
    assert checks["alerts"]["status"] == "error"
    assert f"cannot import {broken}" in checks["alerts"]["detail"]
    assert "timers" in checks   # the rest of the report still ran


# ---- a platform component seen broken is still critical ----

def _health_with(monkeypatch, capsys, paths, run) -> dict:
    monkeypatch.setattr(subprocess, "run", run)
    rc = run_health(paths, as_json=True)
    checks = {c["name"]: c for c in json.loads(capsys.readouterr().out)["checks"]}
    assert rc == 2
    return checks


def test_a_missing_caddy_container_is_exit_2(paths, monkeypatch, capsys):
    def run(cmd, *a, **k):
        if cmd[:2] == ["docker", "inspect"] and cmd[-1] == "boxmunge-caddy":
            return subprocess.CompletedProcess(cmd, 1, "", "Error: No such object: boxmunge-caddy")
        return subprocess.CompletedProcess(cmd, 0, "", "")
    checks = _health_with(monkeypatch, capsys, paths, run)
    assert checks["caddy"]["status"] == "error"


def test_an_inactive_firewall_is_exit_2(paths, monkeypatch, capsys):
    monkeypatch.setattr("os.geteuid", lambda: 0)

    def run(cmd, *a, **k):
        out = "Status: inactive\n" if cmd[:2] == ["ufw", "status"] else ""
        return subprocess.CompletedProcess(cmd, 0, out, "")
    checks = _health_with(monkeypatch, capsys, paths, run)
    assert checks["ufw"]["status"] == "error"


def test_a_missing_docker_cli_is_exit_2(paths, monkeypatch, capsys):
    def run(cmd, *a, **k):
        if cmd[0] == "docker":
            raise FileNotFoundError(2, "No such file or directory", "docker")
        return subprocess.CompletedProcess(cmd, 0, "", "")
    checks = _health_with(monkeypatch, capsys, paths, run)
    assert checks["docker"]["status"] == "error" and "docker CLI not found" in checks["docker"]["detail"]
