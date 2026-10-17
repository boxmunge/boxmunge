"""Test double for the boxmunge-system container.

Path translation and the connect() checks run for real; only the two docker
calls (`docker inspect` and `docker exec`) are replaced. The fake exec maps
container paths back onto the host tree, so a stand-in for age can write its
output file exactly where the real container would.
"""

import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import boxmunge.system_container as sc
from boxmunge.paths import BoxPaths


def healthy_inspect(paths: BoxPaths, *, user: str | None = None) -> dict[str, Any]:
    """A `docker inspect` document for a correctly configured container."""
    owner = paths.projects.stat()
    return {
        "State": {"Status": "running"},
        "Config": {"User": user or f"{owner.st_uid}:{owner.st_gid}"},
        "HostConfig": {"UsernsMode": "host"},
        "Mounts": [
            {"Source": str(m.host), "Destination": m.container}
            for m in sc.system_mounts(paths)
        ],
    }


def host_path(paths: BoxPaths, container: str) -> Path:
    """Invert container_path: map a container path back to the host."""
    for m in sc.system_mounts(paths):
        if container == m.container:
            return m.host
        if m.directory and container.startswith(m.container + "/"):
            return m.host / container.removeprefix(m.container + "/")
    raise AssertionError(f"{container} is not under a system container mount")


def fake_age(paths: BoxPaths, payload: bytes = b"plaintext snapshot") -> Callable:
    """Handler that writes `payload` to age's -o target (via the host tree)."""
    def handle(cmd: list[str]) -> subprocess.CompletedProcess:
        if "-o" in cmd:
            host_path(paths, cmd[cmd.index("-o") + 1]).write_bytes(payload)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    return handle


class FakeSystemContainer:
    """Install with `install(monkeypatch)`; records every exec'd command."""

    def __init__(self, paths: BoxPaths, handler: Callable | None = None) -> None:
        self.paths = paths
        self.inspect: dict[str, Any] | None = healthy_inspect(paths)
        self.handler = handler or fake_age(paths)
        self.calls: list[list[str]] = []

    def _inspect(self, name: str) -> dict[str, Any] | None:
        return self.inspect

    def _exec(self, cmd: list[str], timeout: int = 0, name: str = "") -> subprocess.CompletedProcess:
        self.calls.append(list(cmd))
        return self.handler(cmd)

    def install(self, monkeypatch: pytest.MonkeyPatch) -> "FakeSystemContainer":
        monkeypatch.setattr(sc, "_inspect", self._inspect)
        monkeypatch.setattr(sc, "system_exec", self._exec)
        return self


@pytest.fixture
def system_container(paths: BoxPaths, monkeypatch: pytest.MonkeyPatch) -> FakeSystemContainer:
    """A running, correctly mounted fake system container for `paths`."""
    paths.rclone_config_dir.mkdir(parents=True, exist_ok=True)
    if not paths.backup_key.exists():
        paths.backup_key.write_text("AGE-SECRET-KEY-1TEST\n")
    os.chmod(paths.backup_key, 0o600)
    return FakeSystemContainer(paths).install(monkeypatch)
