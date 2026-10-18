"""systemd control of the daemon and the timers (systemctl stubbed)."""
from __future__ import annotations

import subprocess

import pytest

from boxmunge.userns import daemon_ctl
from boxmunge.userns.daemon_ctl import ControlError, SystemdDaemon, SystemdTimers


def _systemctl(monkeypatch, rc_for):
    calls = []

    def fake(*args):
        calls.append(args)
        return subprocess.CompletedProcess(args, rc_for(args), "", "boom")
    monkeypatch.setattr(daemon_ctl, "_systemctl", fake)
    return calls


def test_timers_are_read_disabled_and_only_enabled_ones_restored(monkeypatch) -> None:
    calls = _systemctl(monkeypatch, lambda a: 0 if a[-1] == "boxmunge-health.timer" else 3)
    timers = SystemdTimers()
    state = timers.state()
    assert state["boxmunge-health.timer"] is True and state["boxmunge-backup.timer"] is False
    monkeypatch.setattr(daemon_ctl, "_systemctl", lambda *a: calls.append(a) or
                        subprocess.CompletedProcess(a, 0, "", ""))
    timers.stop_all()
    timers.restore(state)
    assert calls[0][:2] == ("is-enabled", "--quiet")
    assert calls[-2][:2] == ("disable", "--now")  # survives a reboot
    assert calls[-1] == ("enable", "--now", "boxmunge-health.timer")


def test_a_failed_daemon_start_is_loud(monkeypatch) -> None:
    _systemctl(monkeypatch, lambda a: 1)
    with pytest.raises(ControlError, match="journalctl -u docker.service"):
        SystemdDaemon().start()


def test_a_failed_timer_stop_is_loud(monkeypatch) -> None:
    _systemctl(monkeypatch, lambda a: 1)
    with pytest.raises(ControlError, match="boxmunge timers"):
        SystemdTimers().stop_all()


def test_the_daemon_stop_takes_the_socket_too(monkeypatch) -> None:
    calls = _systemctl(monkeypatch, lambda a: 0)
    SystemdDaemon().stop()
    assert calls == [("stop", "docker.socket", "docker.service")]


def test_answering_asks_docker_info(monkeypatch) -> None:
    monkeypatch.setattr(daemon_ctl, "_run", lambda cmd, **kw: None)
    assert daemon_ctl.daemon_answers()

    def down(cmd, **kw):
        raise daemon_ctl.DockerError("Cannot connect to the Docker daemon")
    monkeypatch.setattr(daemon_ctl, "_run", down)
    assert not daemon_ctl.daemon_answers()
