"""Integration: the overlay's volume entries, resolved by real `docker compose config`.

The overlay writes structured (long-syntax) mounts, so a mount path is never
re-read as `source:target:options`, and they merge with compose.yml's own
entries the way Compose sees them.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from boxmunge import docker
from boxmunge.compose import generate_compose_override

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not on PATH"),
]


def _project(tmp_path: Path, svc: dict) -> Path:
    project_dir = tmp_path / "myapp"
    project_dir.mkdir()
    compose = project_dir / "compose.yml"
    compose.write_text(yaml.safe_dump({"services": {"web": {"image": "alpine", **svc}}}))
    return compose


def _resolve(compose: Path, manifest: dict) -> list[dict]:
    user = yaml.safe_load(compose.read_text())
    (compose.parent / "compose.boxmunge.yml").write_text(
        generate_compose_override(manifest, user_compose=user),
    )
    out = docker.compose_config(
        compose.parent, ["compose.yml", "compose.boxmunge.yml"], project_name="myapp",
    )
    return json.loads(out)["services"]["web"]["volumes"]


_MANIFEST = {
    "project": "myapp",
    "hosts": ["myapp.example.com"],
    "services": {"web": {
        "port": 80, "routes": [{"path": "/"}], "smoke": "smoke.sh",
        "writable": {"persistent": [{"name": "data", "mount": "/app/data"}]},
    }},
}


def test_overlay_volumes_resolve_as_structured_mounts(tmp_path: Path) -> None:
    compose = _project(tmp_path, {"volumes": ["./code:/app/code:ro"]})
    mounts = {v["target"]: v for v in _resolve(compose, _MANIFEST)}
    assert mounts["/app/data"]["type"] == "volume"
    assert mounts["/app/data"]["source"] == "myapp_data"
    assert mounts["/app/data"].get("read_only") is not True
    assert mounts["/boxmunge-scripts"]["type"] == "bind"
    assert mounts["/boxmunge-scripts"]["read_only"] is True
    # Same bind options as the short-syntax mount it replaced (Compose
    # prints its implied create_host_path as an empty `bind`).
    assert mounts["/boxmunge-scripts"]["bind"] == mounts["/app/code"]["bind"]
    assert mounts["/app/code"]["read_only"] is True


def test_overlay_never_reads_a_mount_path_as_options(tmp_path: Path) -> None:
    """Manifest validation refuses `:` in a mount path; the emitter must not
    depend on it. A structured entry keeps the path whole, where the short
    `name:/app/data:ro` string became a read-only mount at /app/data."""
    compose = _project(tmp_path, {})
    manifest = {**_MANIFEST, "services": {"web": {
        "port": 80, "writable": {"persistent": [{"name": "data", "mount": "/app/data:ro"}]},
    }}}
    [mount] = _resolve(compose, manifest)
    assert mount["target"] == "/app/data:ro"
    assert mount.get("read_only") is not True
