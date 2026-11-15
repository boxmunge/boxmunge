"""Integration: a pinned image survives real `docker compose config`.

The overlay's `image: <ref>@<digest>` must be what the merged model a
production start resolves runs, for an image service and a build service
alike. Client-side only: needs the Docker CLI with the compose plugin.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from boxmunge.compose import generate_compose_override
from boxmunge.compose_resolve import resolve_deployed_config
from boxmunge.image_pins import ImagePin

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not on PATH"),
]


def test_the_merged_model_runs_the_pinned_digest(tmp_path: Path) -> None:
    compose = {"services": {"web": {"image": "nginx:1.27"},
                            "app": {"build": ".", "image": "ignored:1"}}}
    (tmp_path / "compose.yml").write_text(yaml.safe_dump(compose))
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    pins = (ImagePin("web", "boxmunge.local/shop/web:autofix-aaaaaaaaaaaa",
                     "sha256:" + "a" * 64, "autofix"),
            ImagePin("app", "boxmunge.local/shop/app:autofix-bbbbbbbbbbbb",
                     "sha256:" + "b" * 64, "autofix"))
    manifest = {"project": "shop", "services": {}}
    (tmp_path / "compose.boxmunge.yml").write_text(
        generate_compose_override(manifest, user_compose=compose, pins=pins))
    model = resolve_deployed_config(tmp_path, ["compose.yml", "compose.boxmunge.yml"], "shop")
    assert {svc: model["services"][svc]["image"] for svc in ("web", "app")} == {
        pin.service: f"{pin.ref}@{pin.digest}" for pin in pins}
