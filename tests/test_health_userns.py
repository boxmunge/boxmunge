"""docker-userns: warn until migrated, error when the daemon disagrees."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from boxmunge.health_checks import userns as hc
from boxmunge.userns import offset
from tests.userns_helpers import S, remap_box, remapped_info

T0 = datetime(2026, 10, 16, tzinfo=timezone.utc)


def test_unmigrated_box_warns_with_the_check_command(paths) -> None:
    check = hc.check_docker_userns(paths)
    assert (check.name, check.status) == ("docker-userns", "warn")
    assert "userns-migrate --check" in check.detail


def test_remapped_box_is_ok(paths, monkeypatch) -> None:
    remap_box(paths, monkeypatch)
    check = hc.check_docker_userns(paths)
    assert check.status == "ok" and str(S) in check.detail


def test_flipped_daemon_is_an_error(paths, monkeypatch) -> None:
    remap_box(paths, monkeypatch)
    info = remapped_info()
    info["Driver"] = "overlayfs"
    monkeypatch.setattr(offset, "docker_info", lambda: info)
    check = hc.check_docker_userns(paths)
    assert check.status == "error" and "storage driver" in check.detail


def test_error_alerts_once_a_day(paths, monkeypatch) -> None:
    remap_box(paths, monkeypatch)
    monkeypatch.setattr(offset, "docker_info", lambda: {**remapped_info(), "SecurityOptions": []})
    sent = []
    monkeypatch.setattr(hc, "notify", lambda p, title, body, **kw: sent.append((title, kw)) or True)
    hc.alert_docker_userns(paths, now=T0)
    hc.alert_docker_userns(paths, now=T0 + timedelta(hours=2))
    hc.alert_docker_userns(paths, now=T0 + timedelta(hours=25))
    assert len(sent) == 2 and sent[0][1]["priority"] == 1


def test_warning_does_not_alert(paths, monkeypatch) -> None:
    sent = []
    monkeypatch.setattr(hc, "notify", lambda *a, **kw: sent.append(a) or True)
    assert hc.alert_docker_userns(paths, now=T0).status == "warn"
    assert sent == []


def test_health_and_doctor_include_the_check() -> None:
    import inspect

    from boxmunge.commands import check, doctor, health_cmd
    assert "check_docker_userns" in inspect.getsource(health_cmd.collect_health)
    assert "check_docker_userns" in inspect.getsource(doctor.run_doctor)
    assert "alert_docker_userns" in inspect.getsource(check.run_check_all)


def test_check_all_exits_critical_on_an_error_even_without_projects(paths, monkeypatch) -> None:
    from boxmunge.commands.check import run_check_all
    remap_box(paths, monkeypatch)
    monkeypatch.setattr(offset, "docker_info", lambda: {**remapped_info(), "SecurityOptions": []})
    monkeypatch.setattr(hc, "notify", lambda *a, **kw: True)
    paths.projects.rmdir()
    assert run_check_all(paths, read_only=False) == 2


def test_unreadable_config_on_an_unremapped_box_only_warns(paths) -> None:
    paths.config_file.write_text("hostname: [unclosed\n")
    check = hc.check_docker_userns(paths)
    assert check.status == "warn" and "cannot tell" in check.detail


def test_unreachable_daemon_on_an_unremapped_box_only_warns(paths, monkeypatch) -> None:
    def down():
        raise offset.RemapError("cannot ask the Docker daemon whether it is remapped: down")
    monkeypatch.setattr(offset, "docker_info", down)
    sent = []
    monkeypatch.setattr(hc, "notify", lambda *a, **kw: sent.append(a) or True)
    assert hc.alert_docker_userns(paths, now=T0).status == "warn"
    assert sent == []


def test_unreachable_daemon_on_a_remapped_box_is_an_error(paths, monkeypatch) -> None:
    remap_box(paths, monkeypatch)
    def down():
        raise offset.RemapError("cannot ask the Docker daemon whether it is remapped: down")
    monkeypatch.setattr(offset, "docker_info", down)
    assert hc.check_docker_userns(paths).status == "error"


def test_undelivered_alert_is_retried_on_the_next_run(paths, monkeypatch) -> None:
    remap_box(paths, monkeypatch)
    monkeypatch.setattr(offset, "docker_info", lambda: {**remapped_info(), "SecurityOptions": []})
    delivered = iter([False, True, True])
    sent = []
    monkeypatch.setattr(hc, "notify",
                        lambda *a, **kw: sent.append(a) or next(delivered))
    hc.alert_docker_userns(paths, now=T0)
    hc.alert_docker_userns(paths, now=T0 + timedelta(minutes=5))
    hc.alert_docker_userns(paths, now=T0 + timedelta(minutes=10))
    assert len(sent) == 2


@pytest.mark.parametrize("content", ["{not json", '["a"]', '{"k": 5}', '{"k": "yesterday"}',
                                     '{"k": "2026-10-16T00:00:00"}'])
def test_unusable_alert_state_is_reported_and_replaced(paths, monkeypatch, capsys,
                                                       content) -> None:
    remap_box(paths, monkeypatch)
    monkeypatch.setattr(offset, "docker_info", lambda: {**remapped_info(), "SecurityOptions": []})
    (paths.state / "userns-alert.json").write_text(content)
    sent = []
    monkeypatch.setattr(hc, "notify", lambda *a, **kw: sent.append(a) or True)
    assert hc.alert_docker_userns(paths, now=T0).status == "error"
    assert len(sent) == 1 and "userns-alert.json" in capsys.readouterr().err
    hc.alert_docker_userns(paths, now=T0 + timedelta(hours=1))
    assert len(sent) == 1
