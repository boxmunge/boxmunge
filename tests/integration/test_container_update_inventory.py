# SPDX-License-Identifier: Apache-2.0
"""container-update works on the deployed model and real image identities
(review findings 15 and 08).

Each test starts a real Compose project from tiny local images. The pull is
the only stub: a real pull needs a registry, so it moves the image tag the
way a pull of a newer upstream image would. Change detection, recreate,
health wait and rollback all run against Docker.
"""
from __future__ import annotations

import uuid

import pytest

import boxmunge.container_update as cu
from boxmunge.container_update import update_target
from boxmunge.container_update_targets import UpdateTarget
from boxmunge.paths import BoxPaths
from tests.integration.conftest import skip_no_docker
from tests.integration.docker_images import (
    BUSYBOX, build_image, compose, container_image_ids, docker, ensure_busybox,
    image_id, tear_down,
)

pytestmark = [pytest.mark.integration, skip_no_docker]


@pytest.fixture
def project(tmp_path, monkeypatch):
    """(paths, name, project_dir, tags): a project dir; tags are removed after."""
    monkeypatch.setattr(cu, "_NO_HEALTHCHECK_GRACE_SEC", 0)
    monkeypatch.setattr(cu, "_HEALTHCHECK_POLL_INTERVAL_SEC", 1)
    name = f"bmupd-{uuid.uuid4().hex[:8]}"
    paths = BoxPaths(root=tmp_path / "bm")
    for d in (paths.state, paths.deploy_state, paths.log_file.parent):
        d.mkdir(parents=True, exist_ok=True)
    project_dir = paths.project_dir(name)
    project_dir.mkdir(parents=True)
    tags: list[str] = []
    yield paths, name, project_dir, tags
    tear_down(project_dir, name, tags)


def _pull_moves(monkeypatch, tag: str, new_source: str) -> None:
    """Stand in for `docker compose pull`: the tag now names a newer image."""
    def pull(project_dir, compose_files=None, *, project_name):
        docker("tag", new_source, tag)
    monkeypatch.setattr(cu, "compose_pull", pull)


def _target(name, project_dir, strategy="leave_broken"):
    return UpdateTarget(name=name, project_dir=project_dir, compose_files=["compose.yml"],
                        strategy=strategy, has_backup=False)


def test_interpolated_image_is_updated(project, monkeypatch):
    paths, name, project_dir, tags = project
    tag, newer = f"{name}-web:1", f"{name}-web-new:1"
    tags += [tag, newer]
    build_image(tag, f"{name}-old")
    new_id = build_image(newer, f"{name}-new")
    (project_dir / "compose.yml").write_text(
        f"services:\n  web:\n    image: ${{WEB_IMAGE:-{tag}}}\n    command: [sleep, '3600']\n")
    compose(project_dir, name, "up", "-d")
    _pull_moves(monkeypatch, tag, newer)

    result = update_target(paths, _target(name, project_dir))

    assert result["status"] == "succeeded", result
    assert container_image_ids(name, "web") == {new_id}


def test_included_image_service_is_updated(project, monkeypatch):
    paths, name, project_dir, tags = project
    tag, newer = f"{name}-db:1", f"{name}-db-new:1"
    tags += [tag, newer]
    build_image(tag, f"{name}-old")
    new_id = build_image(newer, f"{name}-new")
    (project_dir / "db.yml").write_text(
        f"services:\n  db:\n    image: {tag}\n    command: [sleep, '3600']\n")
    (project_dir / "compose.yml").write_text("include:\n  - db.yml\n")
    compose(project_dir, name, "up", "-d")
    _pull_moves(monkeypatch, tag, newer)

    result = update_target(paths, _target(name, project_dir))

    assert result["status"] == "succeeded", result
    assert container_image_ids(name, "db") == {new_id}


def test_expected_service_without_container_is_a_failure_not_no_change(project, monkeypatch):
    paths, name, project_dir, tags = project
    tag = f"{name}-web:1"
    tags.append(tag)
    build_image(tag, f"{name}-old")
    (project_dir / "compose.yml").write_text(
        f"services:\n  web:\n    image: {tag}\n    command: [sleep, '3600']\n")
    monkeypatch.setattr(cu, "compose_pull", lambda *a, **k: None)

    result = update_target(paths, _target(name, project_dir))

    assert result["status"] == "failed"
    assert "web" in result["reason"]


def test_rollback_restores_the_previous_image(project, monkeypatch):
    """The previous image came from a registry, so it has a RepoDigest whose
    manifest digest is not its image ID; rollback must still find it."""
    paths, name, project_dir, tags = project
    old_id = ensure_busybox()
    tag, broken = f"{name}-web:1", f"{name}-web-broken:1"
    tags += [tag, broken]
    docker("tag", BUSYBOX, tag)
    build_image(broken, f"{name}-broken", extra="RUN touch /broken\n")
    (project_dir / "compose.yml").write_text(
        "services:\n  web:\n"
        f"    image: {tag}\n"
        "    command: [sleep, '3600']\n"
        "    healthcheck:\n"
        "      test: [CMD-SHELL, 'test ! -e /broken']\n"
        "      interval: 1s\n      timeout: 1s\n      retries: 1\n")
    compose(project_dir, name, "up", "-d", "--wait")
    _pull_moves(monkeypatch, tag, broken)

    result = update_target(paths, _target(name, project_dir, "rollback_to_previous"))

    assert result["status"] == "failed"
    assert result["rollback_attempted"] is True
    assert result["rollback_succeeded"] is True, result
    assert image_id(tag) == old_id
    assert container_image_ids(name, "web") == {old_id}
