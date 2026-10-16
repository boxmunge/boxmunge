"""Unit tests for the image-name isolation rules (compose_images).

Resolved-model cases live in tests/integration/test_compose_escape_hatches.py.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from boxmunge.compose_images import built_image_name, image_problems, image_warnings

OWN = "boxmunge.invalid/myapp/web"


def _problems(svc: dict, dockerfile: Path | None = None) -> list[str]:
    return image_problems({"web": svc}, "myapp", {"web": dockerfile})


def test_built_image_name_is_under_the_compose_project() -> None:
    assert built_image_name("myapp", "web") == OWN
    assert built_image_name("myapp-staging", "web") == "boxmunge.invalid/myapp-staging/web"


@pytest.mark.parametrize("image", [
    "boxmunge.invalid/projb/web", "boxmunge.invalid/projb/web:latest",
    "BOXMUNGE.INVALID/projb/web", "boxmunge.invalid:443/projb/web",
    "boxmunge.invalid/myapp-other/web",
    "sha256:" + "a" * 64, "3f2a1b0c9d8e", "abc",
])
def test_image_only_service_may_not_name_another_projects_build(image: str) -> None:
    [problem] = _problems({"image": image})
    assert "another project's" in problem or "image ID" in problem


@pytest.mark.parametrize("image", [
    OWN, "boxmunge.invalid/myapp-staging/web", "postgres:16-alpine",
    "ghcr.io/projb/web:1", "myapp-web",
])
def test_public_and_own_images_accepted(image: str) -> None:
    assert _problems({"image": image}) == []


def test_build_tags_refused_with_the_platform_name() -> None:
    [problem] = _problems({"build": {"context": ".", "tags": ["myapp-web:2"]}})
    assert f"boxmunge tags the build {OWN}" in problem


def test_user_image_on_build_service_is_a_warning_not_a_refusal() -> None:
    svc = {"build": {"context": "."}, "image": "postgres:16"}
    assert _problems(svc) == []
    [warning] = image_warnings({"web": svc}, "myapp")
    assert "is ignored" in warning and OWN in warning


@pytest.mark.parametrize("key,ref", [
    ("additional_contexts", {"base": "docker-image://boxmunge.invalid/projb/web"}),
    ("additional_contexts", {"base": "docker-image://sha256:" + "b" * 64}),
    ("dockerfile_inline", "FROM boxmunge.invalid/projb/web\n"),
    ("dockerfile_inline", "FROM alpine AS a\nCOPY --from=boxmunge.invalid/projb/web / /\n"),
    ("dockerfile_inline", "FROM sha256:" + "c" * 64 + "\n"),
    ("args", {"BASE": "boxmunge.invalid/projb/web"}),
])
def test_build_inputs_naming_another_projects_image_refused(key: str, ref) -> None:
    assert _problems({"build": {"context": ".", key: ref}})


def test_dockerfile_stage_references_accepted() -> None:
    inline = ("FROM alpine AS build\nFROM boxmunge.invalid/myapp/web AS base\n"
              "FROM base\nCOPY --from=build / /\nCOPY --from=0 / /\n")
    assert _problems({"build": {"context": ".", "dockerfile_inline": inline}}) == []


def test_dockerfile_file_is_scanned(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG BASE=boxmunge.invalid/projb/web\nFROM ${BASE}\n")
    problems = _problems({"build": {"context": "."}}, dockerfile)
    assert problems and all("Dockerfile" in p for p in problems)
    assert any("projb" in p for p in problems)


@pytest.mark.parametrize("source", ["boxmunge.invalid/projb/web", "sha256:" + "d" * 64])
def test_image_mount_of_another_projects_image_refused(source: str) -> None:
    mount = {"type": "image", "source": source, "target": "/m"}
    assert _problems({"image": "alpine", "volumes": [mount]})


def test_built_service_name_must_be_an_image_component() -> None:
    [problem] = image_problems({"Web_": {"build": "."}}, "myapp", {})
    assert "Rename the service" in problem


@pytest.mark.parametrize("key,value", [
    ("args", {"HOST": "boxmunge.invalid"}),
    ("args", {"HOST": "BoxMunge.Invalid:5000"}),
    ("args", {"BASE": "boxmunge.invalid/myapp"}),
    ("dockerfile_inline", "ARG HOST=boxmunge.invalid\nFROM ${HOST}/projb/web\n"),
    ("dockerfile_inline", "ARG P=boxmunge.invalid/proj\nFROM ${P}b/web\n"),
])
def test_split_platform_names_refused(key: str, value) -> None:
    problems = _problems({"build": {"context": ".", key: value}})
    assert any("other than as this project's own" in p for p in problems)


@pytest.mark.parametrize("key,value", [
    ("args", {"BASE": "boxmunge.invalid/myapp/web:latest"}),
    ("args", {"BASE": "boxmunge.invalid/myapp-staging/web"}),
    ("dockerfile_inline", "ARG BASE=boxmunge.invalid/myapp/web\nFROM ${BASE}\n"),
])
def test_own_full_names_in_args_accepted(key: str, value) -> None:
    assert _problems({"build": {"context": ".", key: value}}) == []


@pytest.mark.parametrize("inline", [
    "FROM ${X:-boxmunge.invalid}/projb/web\n",
    "ARG A=boxmunge\nARG B=.invalid\nFROM ${A}${B}/projb/web\n",
    "ARG A=boxmunge.\nARG B=invalid\nFROM ${A}${B}/projb/web\n",
    "ARG H=boxmunge.invalid\nFROM alpine\nCOPY --from=${H}/projb/web / /\n",
    "FROM alpine\nCOPY --from=boxmunge.invalid/${P}/web / /\n",
    "ARG H=boxmunge.invali\nFROM alpine\nCOPY --from=${H}d/projb/web / /\n",
])
def test_split_names_on_any_dockerfile_line_refused(inline: str) -> None:
    problems = _problems({"build": {"context": ".", "dockerfile_inline": inline}})
    assert any("other than as this project's own" in p for p in problems)


@pytest.mark.parametrize("inline", [
    "FROM alpine\nRUN curl -fsS http://example.invalid/health\n",
    "FROM boxmunge.invalid/myapp/web:${TAG}\n",
    "FROM alpine\nRUN pip install boxmunge.cli\n",
])
def test_unrelated_or_own_mentions_accepted(inline: str) -> None:
    assert _problems({"build": {"context": ".", "dockerfile_inline": inline}}) == []
