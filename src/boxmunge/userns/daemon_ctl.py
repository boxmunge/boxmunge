# SPDX-License-Identifier: Apache-2.0
"""The Docker daemon and the boxmunge timers behind two small interfaces.

systemd on a box; a direct dockerd process in the dind CI job
(tests/integration/userns/dockerd.py), where there is no systemd. Both
stop and start are idempotent: a resumed migration repeats them.
"""
from __future__ import annotations

import subprocess
import time
from typing import Protocol

from boxmunge.docker_run import DockerError, run as _run
from boxmunge.health_checks.hardening import BOXMUNGE_TIMERS

_START_TIMEOUT = 120
_INFO_TIMEOUT = 10


class ControlError(Exception):
    """systemd refused, or the daemon did not come back."""


class DaemonControl(Protocol):
    def stop(self) -> None: ...
    def start(self) -> None: ...


class TimerControl(Protocol):
    def state(self) -> dict[str, bool]: ...
    def stop_all(self) -> None: ...
    def restore(self, state: dict[str, bool]) -> None: ...


def _systemctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["systemctl", *args], capture_output=True, text=True, check=False,
                          timeout=300)


def daemon_answers() -> bool:
    try:
        _run(["docker", "info", "--format", "{{.ID}}"], capture=True, timeout=_INFO_TIMEOUT)
    except DockerError:
        return False
    return True


def wait_for_daemon(timeout: float = _START_TIMEOUT) -> None:
    deadline = time.monotonic() + timeout
    while not daemon_answers():
        if time.monotonic() > deadline:
            raise ControlError(f"the Docker daemon did not answer within {timeout:.0f}s. "
                               f"See: journalctl -u docker.service")
        time.sleep(1)


class SystemdDaemon:
    def stop(self) -> None:
        # The socket too: a docker CLI call would otherwise start the
        # daemon again, on whichever daemon.json is there at that moment.
        result = _systemctl("stop", "docker.socket", "docker.service")
        if result.returncode != 0:
            raise ControlError(f"systemctl stop docker failed: {result.stderr.strip()}")

    def start(self) -> None:
        # A remapped config that would not start can use up docker.service's
        # start limit; then even the original config would be refused.
        _systemctl("reset-failed", "docker.service", "docker.socket")
        result = _systemctl("start", "docker.service")
        if result.returncode != 0:
            raise ControlError(f"systemctl start docker failed: {result.stderr.strip()}. "
                               f"See: journalctl -u docker.service")
        wait_for_daemon()


class SystemdTimers:
    """Timers are disabled, not only stopped, for the downtime: a reboot
    then starts none of them on a box in between two daemons. The journal
    holds which were enabled; those are enabled and started again."""

    def state(self) -> dict[str, bool]:
        return {t: _systemctl("is-enabled", "--quiet", t).returncode == 0
                for t in BOXMUNGE_TIMERS}

    def stop_all(self) -> None:
        result = _systemctl("disable", "--now", *BOXMUNGE_TIMERS)
        if result.returncode != 0:
            raise ControlError(f"systemctl disable --now of the boxmunge timers failed: "
                               f"{result.stderr.strip()}")

    def restore(self, state: dict[str, bool]) -> None:
        enabled = sorted(t for t, on in state.items() if on)
        if enabled:
            result = _systemctl("enable", "--now", *enabled)
            if result.returncode != 0:
                raise ControlError(f"re-enabling timers {enabled} failed: {result.stderr.strip()}")
