"""Integration: no read-write bind mount reaches the files boxmunge reads.

Root re-runs `docker compose up` on a project's own files long after
deploy validated them, so a container that could rewrite compose.yml (or
the manifest, `.env`, the overlay, the kept releases) would hand root an
unvalidated compose file. Real `docker compose config`, real filesystem.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.paths import BoxPaths

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not on PATH"),
]

PROJECT = "guardint"


def _paths(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in (paths.config, paths.projects, paths.deploy_state, paths.logs, paths.caddy_sites):
        d.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(
        "hostname: guard.example.com\nadmin_email: ops@example.com\n"
        "pushover:\n  user_key: u\n  app_token: t\n")
    return paths


def _manifest() -> dict:
    return {
        "schema_version": 2, "id": "01JGUARDINT0000000000000000", "project": PROJECT,
        "source": "bundle", "hosts": [f"{PROJECT}.example.com"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }


def _project(paths: BoxPaths, volumes: list) -> Path:
    project_dir = paths.project_dir(PROJECT)
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "manifest.yml").write_text(yaml.safe_dump(_manifest()))
    (project_dir / "compose.yml").write_text(yaml.safe_dump({"services": {"web": {
        "image": "nginx:1.27-alpine", "network_mode": "none", "volumes": volumes,
    }}}))
    return project_dir


# ---------------------------------------------------------------------------
# (a) A read-write bind mount of the project's own files
# ---------------------------------------------------------------------------

OWN_FILE_MOUNTS = {
    "project root": ".:/app",
    "project root, trailing slash": "./:/app",
    "project root, long syntax": {"type": "bind", "source": ".", "target": "/app"},
    "compose.yml": "./compose.yml:/srv/compose.yml",
    "manifest.yml": "./manifest.yml:/srv/manifest.yml",
    ".env": "./.env:/srv/.env",
    "secrets.env": "./secrets.env:/srv/secrets.env",
    "generated overlay": "./compose.boxmunge.yml:/srv/o.yml",
    "kept releases": "./.releases:/srv/releases",
    "production smoke scripts": "./.releases/live-scripts:/srv/s",
    "staged smoke scripts": "./boxmunge-scripts:/srv/s",
    "CVE suppressions": "./security:/srv/security",
}


@pytest.mark.parametrize("volume", OWN_FILE_MOUNTS.values(), ids=OWN_FILE_MOUNTS.keys())
def test_read_write_mount_of_own_files_is_refused(tmp_path: Path, volume) -> None:
    paths = _paths(tmp_path)
    project_dir = _project(paths, [volume])
    for name in (".env", "secrets.env", "compose.boxmunge.yml"):
        (project_dir / name).write_text("")
    for name in (".releases/live-scripts", "boxmunge-scripts", "security"):
        (project_dir / name).mkdir(parents=True)
    with pytest.raises(ComposeSecurityError, match="read-only"):
        validate_user_compose(project_dir / "compose.yml", paths, project_name=PROJECT)


def test_read_write_mount_of_a_directory_holding_an_env_file_is_refused(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    project_dir = _project(paths, ["./config:/etc/app"])
    doc = yaml.safe_load((project_dir / "compose.yml").read_text())
    doc["services"]["web"]["env_file"] = ["./config/app.env"]
    (project_dir / "compose.yml").write_text(yaml.safe_dump(doc))
    (project_dir / "config").mkdir()
    (project_dir / "config" / "app.env").write_text("A=1\n")
    with pytest.raises(ComposeSecurityError, match="config"):
        validate_user_compose(project_dir / "compose.yml", paths, project_name=PROJECT)


def test_bind_source_inside_a_read_write_bind_source_is_refused(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    project_dir = _project(paths, ["./data:/data", "./data/uploads:/uploads:ro"])
    with pytest.raises(ComposeSecurityError, match="inside"):
        validate_user_compose(project_dir / "compose.yml", paths, project_name=PROJECT)


ACCEPTED = {
    "read-only project root": [".:/app:ro"],
    "data directory": ["./data:/data"],
    "sibling data directories": ["./data:/data", "./media:/media"],
    "read-only compose.yml": ["./compose.yml:/srv/compose.yml:ro"],
    "read-only root plus data": [".:/app:ro", "./data:/app/data"],
}


@pytest.mark.parametrize("volumes", ACCEPTED.values(), ids=ACCEPTED.keys())
def test_data_mounts_and_read_only_mounts_are_accepted(tmp_path: Path, volumes) -> None:
    paths = _paths(tmp_path)
    project_dir = _project(paths, volumes)
    validate_user_compose(project_dir / "compose.yml", paths, project_name=PROJECT)


def _incoming(paths: BoxPaths, volumes: list) -> Path:
    """A candidate release where intake validates it: .releases/incoming/."""
    tree = paths.project_releases(PROJECT) / "incoming" / "tree"
    tree.mkdir(parents=True)
    (tree / "compose.yml").write_text(yaml.safe_dump({"services": {"web": {
        "image": "nginx:1.27-alpine", "volumes": volumes,
    }}}))
    return tree / "compose.yml"


def test_data_mount_of_a_candidate_release_is_accepted(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    compose = _incoming(paths, ["./data:/data", ".:/app:ro"])
    validate_user_compose(compose, paths, project_name=PROJECT)


@pytest.mark.parametrize("volume", [".:/app", "../..:/app", "../../..:/app"],
                         ids=["release root", "kept releases", "project root"])
def test_candidate_release_mounting_the_project_read_write_is_refused(
    tmp_path: Path, volume: str,
) -> None:
    paths = _paths(tmp_path)
    compose = _incoming(paths, [volume])
    with pytest.raises(ComposeSecurityError, match="read-only"):
        validate_user_compose(compose, paths, project_name=PROJECT)


def test_absolute_mount_of_the_kept_releases_is_refused(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    releases = paths.project_releases(PROJECT)
    compose = _incoming(paths, [f"{releases}:/r"])
    with pytest.raises(ComposeSecurityError, match="read-only"):
        validate_user_compose(compose, paths, project_name=PROJECT)


def test_git_project_mounting_its_checkout_read_write_is_refused(tmp_path: Path) -> None:
    """A git project's compose.yml is a symlink into repo/."""
    paths = _paths(tmp_path)
    project_dir = paths.project_dir(PROJECT)
    (project_dir / "repo").mkdir(parents=True)
    (project_dir / "repo" / "compose.yml").write_text(yaml.safe_dump({"services": {"web": {
        "image": "nginx:1.27-alpine", "volumes": ["./repo:/app"],
    }}}))
    (project_dir / "compose.yml").symlink_to(project_dir / "repo" / "compose.yml")
    with pytest.raises(ComposeSecurityError, match="read-only"):
        validate_user_compose(project_dir / "compose.yml", paths, project_name=PROJECT)


def test_profile_off_does_not_relax_the_rule(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    project_dir = _project(paths, [".:/app"])
    with pytest.raises(ComposeSecurityError, match="read-only"):
        validate_user_compose(project_dir / "compose.yml", paths, project_name=PROJECT,
                              off_services={"web"})


# ---------------------------------------------------------------------------
# Review 67: a provider service, and a hostile service behind a profile,
# both bypassed validation before. Real `docker compose config`.
# ---------------------------------------------------------------------------


def _validate_doc(paths: BoxPaths, doc: dict, *, off: set[str] | None = None) -> None:
    project_dir = paths.project_dir(PROJECT)
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "manifest.yml").write_text(yaml.safe_dump(_manifest()))
    (project_dir / "compose.yml").write_text(yaml.safe_dump(doc))
    validate_user_compose(project_dir / "compose.yml", paths,
                          project_name=PROJECT, off_services=off or set())


def test_provider_service_is_refused(tmp_path: Path) -> None:
    """`provider.type` is run on the host by Compose; a path type can even
    name a file the containers write."""
    paths = _paths(tmp_path)
    project_dir = paths.project_dir(PROJECT)
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "data").mkdir()
    (project_dir / "data" / "evil").write_text("#!/bin/sh\n")
    with pytest.raises(ComposeSecurityError, match="provider"):
        _validate_doc(paths, {"services": {
            "web": {"image": "nginx:1.27-alpine", "network_mode": "none",
                    "volumes": ["./data:/d"]},
            "thing": {"provider": {"type": "./data/evil", "options": {"a": "b"}}},
        }})


def test_hostile_service_behind_an_inactive_profile_is_refused(tmp_path: Path) -> None:
    """A profiled service is still started by `--profile` or as a dependency,
    so its hostile keys are validated like any other (reviewer item 4)."""
    paths = _paths(tmp_path)
    with pytest.raises(ComposeSecurityError, match="privileged"):
        _validate_doc(paths, {"services": {
            "web": {"image": "nginx:1.27-alpine", "network_mode": "none"},
            "dbtool": {"image": "postgres:16-alpine", "profiles": ["tools"],
                       "privileged": True},
        }})


def test_profiled_backup_service_mounting_the_project_is_refused(tmp_path: Path) -> None:
    """The restore starts the backup service; a profiled one that mounts the
    project root read-write must not pass validation."""
    paths = _paths(tmp_path)
    with pytest.raises(ComposeSecurityError, match="read-only"):
        _validate_doc(paths, {"services": {
            "web": {"image": "nginx:1.27-alpine", "network_mode": "none"},
            "dbtool": {"image": "postgres:16-alpine", "profiles": ["tools"],
                       "volumes": [".:/app"]},
        }})


def test_label_file_outside_the_project_is_refused(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    with pytest.raises(ComposeSecurityError, match="label_file"):
        _validate_doc(paths, {"services": {"web": {
            "image": "nginx:1.27-alpine", "network_mode": "none",
            "label_file": "/etc/hosts",
        }}})


def test_rw_mount_of_the_dir_holding_a_label_file_is_refused(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    project_dir = paths.project_dir(PROJECT)
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "cfg").mkdir()
    (project_dir / "cfg" / "labels").write_text("a=b\n")
    with pytest.raises(ComposeSecurityError, match="read-only"):
        _validate_doc(paths, {"services": {"web": {
            "image": "nginx:1.27-alpine", "network_mode": "none",
            "label_file": "./cfg/labels", "volumes": ["./cfg:/cfg"],
        }}})
