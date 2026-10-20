"""Integration: compose validation against real `docker compose config`.

`docker compose config` is client-side only, so these need the Docker CLI
(with the compose plugin) but no running daemon work beyond that.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from boxmunge.compose import generate_compose_override, load_user_compose
from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.paths import BoxPaths

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not on PATH"),
]


def _project(tmp_path: Path, files: dict[str, object]) -> tuple[BoxPaths, Path]:
    paths = BoxPaths(root=tmp_path / "bm")
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True)
    for name, content in files.items():
        path = project_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else yaml.safe_dump(content))
    return paths, project_dir / "compose.yml"


def _validate(paths: BoxPaths, compose: Path) -> None:
    validate_user_compose(compose, paths, project_name="myapp")


def test_capability_from_bundled_env_rejected(tmp_path: Path) -> None:
    paths, compose = _project(tmp_path, {
        "compose.yml": {"services": {"web": {"image": "nginx", "cap_add": ["${C}"]}}},
        ".env": "C=SYS_ADMIN\n",
    })
    with pytest.raises(ComposeSecurityError, match="cap_add"):
        _validate(paths, compose)


def test_extends_inside_project_is_merged_then_checked(tmp_path: Path) -> None:
    paths, compose = _project(tmp_path, {
        "compose.yml": {"services": {"web": {
            "extends": {"file": "base.yml", "service": "app"},
        }}},
        "base.yml": {"services": {"app": {"image": "nginx", "pid": "host"}}},
    })
    with pytest.raises(ComposeSecurityError, match="pid"):
        _validate(paths, compose)


def test_included_service_is_checked(tmp_path: Path) -> None:
    paths, compose = _project(tmp_path, {
        "compose.yml": {"include": ["parts/sidecar.yml"],
                        "services": {"web": {"image": "nginx"}}},
        "parts/sidecar.yml": {"services": {"sidecar": {
            "image": "alpine", "volumes": ["/:/host"],
        }}},
    })
    with pytest.raises(ComposeSecurityError, match="service sidecar"):
        _validate(paths, compose)


def test_benign_project_with_include_passes_and_overlay_sees_all(tmp_path: Path) -> None:
    paths, compose = _project(tmp_path, {
        "compose.yml": {"include": ["parts/db.yml"],
                        "services": {"web": {"image": "nginx", "volumes": ["./data:/data"]}}},
        "parts/db.yml": {"services": {"db": {"image": "postgres:16-alpine"}}},
    })
    _validate(paths, compose)
    assert set(load_user_compose(compose, "myapp")["services"]) == {"web", "db"}


def test_include_outside_project_rejected_before_resolution(tmp_path: Path) -> None:
    paths, compose = _project(tmp_path, {
        "compose.yml": {"include": ["../other/inc.yml"], "services": {}},
    })
    (paths.projects / "other").mkdir()
    (paths.projects / "other" / "inc.yml").write_text("services: {}\n")
    with pytest.raises(ComposeSecurityError, match="outside the project"):
        _validate(paths, compose)


def test_on_box_env_file_absent_from_bundle_is_not_needed(tmp_path: Path) -> None:
    """A bundle's compose may name secrets.env, which only exists on the box.

    Deploy validates the bundle in an extraction directory where that file is
    absent; resolution must not try to read service env files (regression:
    every such project's deploy was refused with "env file not found").
    """
    paths, compose = _project(tmp_path, {
        "compose.yml": {"services": {"web": {
            "image": "nginx", "env_file": ["project.env", "secrets.env"],
        }}},
        "project.env": "MODE=prod\n",
    })
    assert not (compose.parent / "secrets.env").exists()
    _validate(paths, compose)


def test_env_file_outside_project_still_refused_without_resolution(tmp_path: Path) -> None:
    paths, compose = _project(tmp_path, {
        "compose.yml": {"services": {"web": {
            "image": "nginx", "env_file": ["../../elsewhere.env"],
        }}},
    })
    with pytest.raises(ComposeSecurityError, match="env_file"):
        _validate(paths, compose)


def test_env_file_placeholder_is_removed_after_validation(tmp_path: Path) -> None:
    paths, compose = _project(tmp_path, {
        "compose.yml": {"services": {"web": {"image": "nginx", "env_file": ["secrets.env"]}}},
    })
    _validate(paths, compose)
    assert not (compose.parent / "secrets.env").exists()


def test_read_only_false_survives_real_config_and_wins_in_the_overlay(tmp_path: Path) -> None:
    """Compose's JSON output drops `read_only: false`; the user's literal
    value is restored from compose.yml so the overlay leaves it alone."""
    _, compose = _project(tmp_path, {"compose.yml": {"services": {
        "db": {"image": "postgres:16", "read_only": False},
        "web": {"image": "nginx"},
    }}})
    user_compose = load_user_compose(compose, "myapp")
    assert user_compose["services"]["db"]["read_only"] is False
    manifest = {"project": "myapp", "services": {
        "db": {"internal": True}, "web": {"port": 80, "routes": [{"path": "/"}]}}}
    services = yaml.safe_load(generate_compose_override(
        manifest, user_compose=user_compose))["services"]
    assert "read_only" not in services["db"]
    assert services["web"]["read_only"] is True
