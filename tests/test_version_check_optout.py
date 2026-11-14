"""version_check.enabled: false in boxmunge.yml: the box sends the
version-check service nothing, asks GitHub nothing instead, and says plainly
everywhere that it is no longer discovering updates."""
import json
from unittest.mock import patch

import pytest

from boxmunge.commands.auto_update_cmd import run_auto_update
from boxmunge.paths import BoxPaths
from boxmunge.report_failure import report_failure
from boxmunge.upgrade_discovery import discover_update
from boxmunge.version import write_installed_version

BASE = "hostname: t\nadmin_email: a@b\n"
OFF = BASE + "version_check:\n  enabled: false\n"


@pytest.fixture
def no_network():
    """Every way the box reaches the service or GitHub, failing the test if used."""
    def refuse(*args, **kwargs):
        raise AssertionError("the box made a network call with version checks off")
    with patch("urllib.request.OpenerDirector.open", side_effect=refuse), \
            patch("urllib.request.urlopen", side_effect=refuse):
        yield


@pytest.fixture
def box(paths: BoxPaths) -> BoxPaths:
    (paths.root / "upgrade-state").mkdir(exist_ok=True)
    paths.blocklist.write_text("{}")
    write_installed_version(paths, "0.3.0", "abc1234")
    paths.config_file.write_text(OFF)
    return paths


@pytest.fixture(autouse=True)
def healthy_os_updates(monkeypatch) -> None:
    from datetime import timedelta
    from boxmunge.os_updates import OsUpdateStatus
    monkeypatch.setattr("boxmunge.os_updates.inspect_os_updates",
                        lambda: OsUpdateStatus(stamp_age=timedelta(hours=1)))


class TestDiscovery:
    @pytest.mark.parametrize("mode", ["security", "breakfix", "latest"])
    def test_asks_nobody_and_names_the_way_to_upgrade(self, box, no_network, mode):
        result = discover_update(box, mode=mode)
        assert result["action"] == "error"
        assert "version_check.enabled: false" in result["message"]
        assert "upgrade --target X.Y.Z" in result["message"]

    def test_an_unreadable_config_sends_nothing(self, box, no_network):
        box.config_file.write_text("version_check: [\n")
        result = discover_update(box, mode="latest")
        assert result["action"] == "error"
        assert "boxmunge.yml" in result["message"]


class TestFailureReport:
    def test_is_not_sent_and_says_why(self, box, no_network, capsys):
        assert report_failure("0.3.1", "0.3.0", "apply", paths=box) is False
        assert "version_check.enabled: false" in capsys.readouterr().err

    def test_an_unreadable_config_sends_nothing(self, box, no_network, capsys):
        box.config_file.write_text("version_check: {enabled: maybe}\n" + BASE)
        assert report_failure("0.3.1", "0.3.0", "apply", paths=box) is False
        assert "version_check.enabled" in capsys.readouterr().err


class TestAutoUpdate:
    def test_skips_discovery_without_failing_the_timer(self, box, no_network, capsys):
        with patch("boxmunge.os_update_alert.record_os_updates") as os_updates:
            assert run_auto_update(box) == 0
        os_updates.assert_called_once()  # OS update alerts are local and keep working
        assert "version checks are off" in capsys.readouterr().out
        entries = [json.loads(line) for line in
                   (box.root / "logs" / "boxmunge.log").read_text().splitlines()]
        assert any("version checks are off" in e["msg"] for e in entries)
        assert not box.update_discovery_state.exists()


class TestReports:
    @pytest.fixture(autouse=True)
    def _docker(self, docker_down):
        """doctor probes the docker CLI."""

    def test_health_says_updates_are_not_discovered(self, box):
        from boxmunge.health_checks.platform_updates import check_platform_updates
        check = check_platform_updates(box)
        assert check.status == "warn"
        assert "discovers no releases" in check.detail

    def test_health_is_unchanged_with_checks_on(self, box):
        from boxmunge.health_checks.platform_updates import check_platform_updates
        box.config_file.write_text(BASE)
        assert check_platform_updates(box).status == "ok"

    def test_doctor_warns(self, box, capsys):
        from boxmunge.commands.doctor import run_doctor
        run_doctor(box, as_json=True)
        results = {r["name"]: r for r in json.loads(capsys.readouterr().out)}
        assert results["Update discovery"]["status"] == "WARN"
        assert "discovers no releases" in results["Update discovery"]["detail"]

    def test_doctor_is_silent_with_checks_on(self, box, capsys):
        from boxmunge.commands.doctor import run_doctor
        box.config_file.write_text(BASE)
        run_doctor(box, as_json=True)
        names = {r["name"] for r in json.loads(capsys.readouterr().out)}
        assert "Update discovery" not in names


class TestNobodyChose:
    @pytest.fixture(autouse=True)
    def _docker(self, docker_down):
        """doctor probes the docker CLI."""

    def _doctor(self, box, capsys):
        from boxmunge.commands.doctor import run_doctor
        code = run_doctor(box, as_json=True)
        return code, {r["name"]: r for r in json.loads(capsys.readouterr().out)}

    def test_doctor_warns_when_the_key_is_absent(self, box, capsys):
        box.config_file.write_text(BASE)
        _, results = self._doctor(box, capsys)
        assert results["Version check choice"]["status"] == "WARN"
        assert "agent-help rules" in results["Version check choice"]["detail"]

    @pytest.mark.parametrize("value", ["true", "false"])
    def test_doctor_is_quiet_once_chosen(self, box, capsys, value):
        box.config_file.write_text(BASE + f"version_check:\n  enabled: {value}\n")
        _, results = self._doctor(box, capsys)
        assert "Version check choice" not in results

    def test_the_note_is_a_warning_not_a_failure(self, box, capsys):
        """A FAIL here would count against an upgrade's probation."""
        box.config_file.write_text(BASE)
        _, results = self._doctor(box, capsys)
        assert results["Version check choice"]["status"] != "FAIL"

    def test_an_unchosen_box_still_checks(self, box):
        from boxmunge.version_check_optout import version_checks_off
        box.config_file.write_text(BASE)
        assert version_checks_off(box) is False
