"""Daemon and timer control for the dind job (no systemd there)."""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

DAEMON_JSON = Path("/etc/docker/daemon.json")
PRIOR = Path("/etc/docker/daemon.json.prior")
LOG = Path("/var/log/dockerd.log")
BUSYBOX = "busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"


def _wait(ready, what: str, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while not ready():
        if time.monotonic() > deadline:
            tail = LOG.read_text(errors="replace")[-4000:] if LOG.exists() else ""
            raise RuntimeError(f"timed out waiting for {what}\n{tail}")
        time.sleep(0.5)


def _quiet(*cmd: str) -> int:
    return subprocess.run(list(cmd), capture_output=True, check=False).returncode


def _dockerd_running() -> bool:
    """A live dockerd. A crash test's dockerd outlives the forked process
    that started it and is left a zombie (the container's PID 1 does not
    reap), which pgrep would still count."""
    for stat in Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = stat.read_text().rsplit(")", 1)
            name = fields[0].split("(", 1)[1]
        except (OSError, IndexError):
            continue  # gone since the listing
        if name == "dockerd" and fields[1].split()[0] != "Z":
            return True
    return False


class ProcessDaemon:
    """dockerd as a child process; the same stop/start contract as systemd."""

    def stop(self) -> None:
        _quiet("pkill", "-TERM", "-x", "dockerd")
        _wait(lambda: not _dockerd_running(), "dockerd to exit")

    def start(self) -> None:
        with LOG.open("ab") as log:
            subprocess.Popen(["dind", "dockerd"], stdout=log, stderr=subprocess.STDOUT,
                             start_new_session=True)
        _wait(lambda: _quiet("docker", "info") == 0, "dockerd to answer")


class FakeTimers:
    """Records what the engine stops and restores."""

    def __init__(self, enabled: dict[str, bool] | None = None) -> None:
        self.enabled = dict(enabled or {"boxmunge-health.timer": True,
                                        "boxmunge-backup.timer": True})
        self.calls: list[tuple[str, str]] = []

    def state(self) -> dict[str, bool]:
        return dict(self.enabled)

    def stop_all(self) -> None:
        self.calls.append(("stop", "*"))

    def restore(self, state: dict[str, bool]) -> None:
        self.calls.append(("restore", json.dumps(state, sort_keys=True)))


def write_daemon_json(doc: dict) -> None:
    DAEMON_JSON.write_text(json.dumps(doc, indent=2) + "\n")


def prior_daemon_json() -> dict:
    return json.loads(PRIOR.read_text())
