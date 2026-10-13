"""Fleet loops isolate per-project failures (audits D-02, D-05, C-15).

One project with a malformed manifest or a corrupt state file must be
reported loudly and must not stop the loop from reaching every other
project. The command's exit code must show that a project failed.
"""

import json

import pytest
import yaml

from boxmunge.commands import check as check_mod
from boxmunge.commands.check import run_check_all
from boxmunge.commands.health_cmd import (
    check_config_drift,
    check_lifecycle_blocked,
    check_project_containers,
)
from boxmunge.commands.status import run_status
from boxmunge.commands.validate import run_validate
from boxmunge.paths import BoxPaths
from boxmunge.tui.data import load_all_project_status

CONFIG = "hostname: box.example.com\nadmin_email: ops@example.com\n"


def _manifest(name: str) -> dict:
    return {
        "schema_version": 3, "id": "01TEST", "project": name,
        "source": "bundle", "hosts": [f"{name}.example.com"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }


def _write_project(paths: BoxPaths, name: str) -> None:
    paths.project_dir(name).mkdir(parents=True, exist_ok=True)
    paths.project_manifest(name).write_text(yaml.dump(_manifest(name)))


@pytest.fixture
def fleet(paths: BoxPaths) -> BoxPaths:
    """Three healthy projects (aaa, bbb, ccc) and a valid host config."""
    paths.config_file.write_text(CONFIG)
    for name in ("aaa", "bbb", "ccc"):
        _write_project(paths, name)
    return paths


def _break_manifest(paths: BoxPaths, name: str) -> None:
    paths.project_manifest(name).write_text("services: [\n")


def _corrupt(path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"status": "ok"')


def _health(paths: BoxPaths, name: str) -> dict:
    return json.loads(paths.project_health_state(name).read_text())


# ---------- check-all ----------


class TestCheckAllIsolation:
    def test_malformed_manifest_does_not_stop_the_fleet(
        self, fleet: BoxPaths, capsys,
    ) -> None:
        _break_manifest(fleet, "aaa")
        rc = run_check_all(fleet, read_only=False)
        err = capsys.readouterr().err
        assert "ERROR" in err and "aaa" in err
        assert str(fleet.project_manifest("aaa")) in err
        # Every other project was still checked and recorded.
        assert _health(fleet, "bbb")["status"] == "ok"
        assert _health(fleet, "ccc")["status"] == "ok"
        assert rc != 0

    def test_malformed_manifest_feeds_the_alerting_state(
        self, fleet: BoxPaths,
    ) -> None:
        """The broken project's failure reaches health state with its cause,
        so the normal threshold alert fires instead of the project silently
        vanishing from monitoring."""
        _break_manifest(fleet, "aaa")
        run_check_all(fleet, read_only=False)
        state = _health(fleet, "aaa")
        assert state["consecutive_failures"] == 1
        assert "not valid YAML" in state["failure_reason"]

    def test_corrupt_health_state_does_not_stop_the_fleet(
        self, fleet: BoxPaths, capsys,
    ) -> None:
        _corrupt(fleet.project_health_state("aaa"))
        rc = run_check_all(fleet, read_only=False)
        err = capsys.readouterr().err
        assert "aaa" in err
        assert str(fleet.project_health_state("aaa")) in err
        assert _health(fleet, "bbb")["status"] == "ok"
        assert _health(fleet, "ccc")["status"] == "ok"
        assert rc != 0

    def test_corrupt_quarantine_state_does_not_stop_the_fleet(
        self, fleet: BoxPaths, capsys,
    ) -> None:
        _corrupt(fleet.project_quarantine_state("aaa"))
        rc = run_check_all(fleet, read_only=False)
        assert "aaa" in capsys.readouterr().err
        assert _health(fleet, "ccc")["status"] == "ok"
        assert rc != 0

    def test_read_only_mode_isolates_too(
        self, fleet: BoxPaths, monkeypatch, capsys,
    ) -> None:
        checked: list[str] = []
        real = check_mod.run_check

        def _spy(name, paths, verbose=True):
            checked.append(name)
            return real(name, paths, verbose)

        monkeypatch.setattr(check_mod, "run_check", _spy)
        _corrupt(fleet.project_quarantine_state("aaa"))
        rc = run_check_all(fleet, read_only=True)
        assert checked == ["bbb", "ccc"]
        assert rc != 0
        assert not fleet.project_health_state("bbb").exists()

    def test_malformed_host_config_is_reported_and_checks_still_run(
        self, fleet: BoxPaths, capsys,
    ) -> None:
        fleet.config_file.write_text("hostname: [\n")
        rc = run_check_all(fleet, read_only=False)
        err = capsys.readouterr().err
        assert "ERROR" in err and str(fleet.config_file) in err
        assert _health(fleet, "ccc")["status"] == "ok"
        assert rc != 0

    def test_failure_is_written_to_the_operational_log(
        self, fleet: BoxPaths,
    ) -> None:
        _corrupt(fleet.project_health_state("aaa"))
        run_check_all(fleet, read_only=False)
        entries = [
            json.loads(line)
            for line in fleet.log_file.read_text().splitlines() if line
        ]
        assert any(
            e["level"] == "error" and e.get("project") == "aaa"
            for e in entries
        )

    def test_healthy_fleet_still_exits_zero(self, fleet: BoxPaths) -> None:
        assert run_check_all(fleet, read_only=False) == 0


# ---------- status ----------


class TestStatusIsolation:
    def test_corrupt_state_reported_and_other_rows_shown(
        self, fleet: BoxPaths, capsys,
    ) -> None:
        _corrupt(fleet.project_deploy_state("bbb"))
        rc = run_status(fleet)
        captured = capsys.readouterr()
        assert "aaa" in captured.out and "ccc" in captured.out
        assert "ERROR" in captured.out
        assert str(fleet.project_deploy_state("bbb")) in captured.err
        assert rc == 1

    def test_corrupt_state_json_row(self, fleet: BoxPaths, capsys) -> None:
        _corrupt(fleet.project_quarantine_state("bbb"))
        rc = run_status(fleet, as_json=True)
        rows = json.loads(capsys.readouterr().out)
        by_name = {r["project"]: r for r in rows}
        assert set(by_name) == {"aaa", "bbb", "ccc"}
        assert by_name["bbb"]["raw_status"] == "error"
        assert "bbb" in by_name["bbb"]["error"]
        assert rc == 1


# ---------- health ----------


class TestHealthIsolation:
    def test_config_drift_reports_unreadable_manifest(
        self, fleet: BoxPaths,
    ) -> None:
        _break_manifest(fleet, "aaa")
        check = check_config_drift(fleet)
        assert check.status == "error"
        assert "aaa" in check.detail

    def test_lifecycle_reports_corrupt_quarantine_state(
        self, fleet: BoxPaths,
    ) -> None:
        _corrupt(fleet.project_quarantine_state("aaa"))
        check = check_lifecycle_blocked(fleet)
        assert check.status == "error"
        assert "aaa" in check.detail

    def test_project_containers_reports_corrupt_state(
        self, fleet: BoxPaths, monkeypatch,
    ) -> None:
        import subprocess

        def _fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, stdout="[{}]", stderr="")

        monkeypatch.setattr(
            "boxmunge.commands.health_cmd.subprocess.run", _fake_run,
        )
        _corrupt(fleet.project_quarantine_state("aaa"))
        check = check_project_containers(fleet)
        assert check.status == "error"
        assert "aaa" in check.detail


# ---------- validate / TUI ----------


def test_validate_malformed_manifest_is_a_clean_error(
    fleet: BoxPaths, capsys,
) -> None:
    _break_manifest(fleet, "aaa")
    assert run_validate("aaa", fleet) == 1
    captured = capsys.readouterr()
    assert "ERROR" in captured.err
    assert "not valid YAML" in captured.err


def test_tui_status_survives_corrupt_state(fleet: BoxPaths) -> None:
    _corrupt(fleet.project_health_state("bbb"))
    rows = {s.name: s for s in load_all_project_status(fleet)}
    assert set(rows) == {"aaa", "bbb", "ccc"}
    assert rows["bbb"].status == "error"
    assert str(fleet.project_health_state("bbb")) in rows["bbb"].failure_reason
