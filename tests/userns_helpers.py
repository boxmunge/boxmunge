"""Turn a unit test's box into a remapped one (see tests/conftest.py)."""
from __future__ import annotations

import json
from typing import Any

S = 1048576  # the first 65536-aligned block >= 1,000,000

UNREMAPPED_INFO: dict[str, Any] = {
    "SecurityOptions": ["name=seccomp,profile=builtin", "name=cgroupns"],
    "Driver": "overlayfs",
    "DriverStatus": [["driver-type", "io.containerd.snapshotter.v1"]],
    "DockerRootDir": "/var/lib/docker",
}


def remapped_info(s: int = S) -> dict[str, Any]:
    return {
        "SecurityOptions": ["name=seccomp,profile=builtin", "name=userns", "name=cgroupns"],
        "Driver": "overlay2",
        "DriverStatus": [["Backing Filesystem", "extfs"]],
        "DockerRootDir": f"/var/lib/docker/{s}.{s}",
    }


def remap_box(paths, monkeypatch, s: int = S) -> int:
    """Write every remap source for offset `s` and make the daemon report it."""
    from boxmunge.userns import offset

    for name in ("subuid", "subgid"):
        (offset.ETC / name).write_text(f"deploy:100000:65536\n{offset.REMAP_NAME}:{s}:65536\n")
    (offset.ETC / "docker").mkdir(exist_ok=True)
    (offset.ETC / "docker" / "daemon.json").write_text(json.dumps({
        "userns-remap": offset.DAEMON_REMAP_VALUE, "storage-driver": "overlay2",
        "features": {"containerd-snapshotter": False}}))
    paths.config.mkdir(parents=True, exist_ok=True)
    base = (paths.config_file.read_text() if paths.config_file.exists()
            else "hostname: box.example.com\nadmin_email: ops@example.com\n")
    paths.config_file.write_text(base + f"userns:\n  name: {offset.REMAP_NAME}\n  offset: {s}\n")
    monkeypatch.setattr(offset, "docker_info", lambda: remapped_info(s))
    return s
