"""Unit tests for the image-namespace isolation rules (compose_images).

Resolved-model cases live in tests/integration/test_compose_escape_hatches.py.
"""
from __future__ import annotations

import pytest

from boxmunge.compose_images import image_problems, owner


@pytest.mark.parametrize("repo,projects,expected", [
    ("foo-web", {"foo"}, "foo"),
    ("foo_web", {"foo"}, "foo"),
    ("foo/web", {"foo"}, "foo"),
    ("foo", {"foo"}, None),             # bare names are where official images live
    ("foobar-web", {"foo"}, None),
    ("foo-bar-web", {"foo", "foo-bar"}, "foo-bar"),
    ("foo-baz", {"foo", "foo-bar"}, "foo"),
])
def test_owner_is_longest_project_prefix(repo, projects, expected) -> None:
    assert owner(repo, projects) == expected


def _problems(svc: dict, others=()) -> list[str]:
    return image_problems({"web": svc}, "myapp", others)


@pytest.mark.parametrize("image", [
    "myapp-web", "myapp-web:1.2", "myapp/web@sha256:" + "0" * 64, "myapp_web:latest",
])
def test_namespaced_build_names_accepted(image: str) -> None:
    assert _problems({"build": ".", "image": image}, ["projb"]) == []


@pytest.mark.parametrize("image", [
    "myapp", "postgres:16", "library/myapp-web", "docker.io/myapp-web",
    "localhost/myapp-web", "localhost:5000/myapp-web", "projb-web",
])
def test_build_names_outside_namespace_refused(image: str) -> None:
    [problem] = _problems({"build": ".", "image": image})
    assert "Name it myapp-<name> (for example myapp-web)" in problem


def test_string_tag_list_checked() -> None:
    [problem] = _problems({"build": {"context": ".", "tags": ["myapp-web", "nginx"]}})
    assert "'nginx'" in problem


@pytest.mark.parametrize("image", [
    "projb-web", "projb-web:1", "docker.io/projb-web", "index.docker.io/library/projb-web",
])
def test_image_only_service_may_not_run_another_projects_build(image: str) -> None:
    [problem] = _problems({"image": image}, ["projb"])
    assert "'projb'" in problem and "build your own as myapp-<name>" in problem


@pytest.mark.parametrize("image", [
    "postgres:16-alpine", "ghcr.io/projb-web:1", "myapp-web", "projbx-web",
])
def test_image_only_service_public_and_own_images_accepted(image: str) -> None:
    assert _problems({"image": image}, ["projb"]) == []
