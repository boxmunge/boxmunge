"""Unit tests for build-input confinement and the daemon/hook/device rules.

The resolved-model cases (real `docker compose config`) live in
tests/integration/test_compose_escape_hatches.py; these cover the literal
shapes Compose normalises away (string build, list additional_contexts)
and the exact advice each rejection gives.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from boxmunge.compose_build import build_problems
from boxmunge.compose_service_rules import service_findings
from boxmunge.paths import BoxPaths


@pytest.fixture
def project(paths: BoxPaths) -> Path:
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True)
    return project_dir


def _problems(build, project: Path) -> list[str]:
    return build_problems("web", build, project, (project,))


def test_string_build_context_outside_project(project: Path) -> None:
    [problem] = _problems("../..", project)
    assert "build context '../..'" in problem and "inside the project" in problem


def test_list_form_additional_context_confined(project: Path) -> None:
    [problem] = _problems({"context": ".", "additional_contexts": ["host=/srv"]}, project)
    assert "additional_contexts.host" in problem


def test_relative_dockerfile_resolves_against_context(project: Path) -> None:
    (project / "sub").mkdir()
    # ../Dockerfile from ./sub is still inside the project.
    assert _problems({"context": "./sub", "dockerfile": "../Dockerfile"}, project) == []
    [problem] = _problems({"context": "./sub", "dockerfile": "../../x"}, project)
    assert "build.dockerfile" in problem


def test_unknown_build_key_refused(project: Path) -> None:
    [problem] = _problems({"context": ".", "output": "type=local,dest=/"}, project)
    assert "build.output is not a build option boxmunge knows" in problem


def test_extension_and_plain_keys_accepted(project: Path) -> None:
    build = {"context": ".", "x-note": 1, "args": {"A": "1"}, "target": "prod",
             "secrets": ["token"], "dockerfile_inline": "FROM alpine\n"}
    assert _problems(build, project) == []


@pytest.mark.parametrize("network", ["none", "default", " Default ", "host"])
def test_unnamed_build_networks_left_to_hardening(project: Path, network: str) -> None:
    assert _problems({"context": ".", "network": network}, project) == []


def _findings(svc: dict, paths: BoxPaths, project: Path) -> list[str]:
    return [f.key for f in service_findings(svc, project, paths, (project,))]


@pytest.mark.parametrize("svc,key", [
    ({"use_api_socket": True}, "use_api_socket"),
    ({"post_start": [{"command": "id"}, {"command": "id", "privileged": True}]},
     "post_start[1].privileged"),
    ({"pre_stop": [{"command": "id", "privileged": "yes"}]}, "pre_stop[0].privileged"),
    ({"cgroup": " HOST "}, "cgroup"),
    ({"gpus": [{"driver": "nvidia", "count": 1}]}, "gpus"),
    ({"build": {"context": ".", "entitlements": ["security.insecure"]}}, "build.entitlements"),
])
def test_hardening_findings(paths: BoxPaths, project: Path, svc: dict, key: str) -> None:
    assert key in _findings(svc, paths, project)


@pytest.mark.parametrize("entry", [
    {"type": "npipe", "source": "/var/run/docker.sock", "target": "/s"},
    {"type": "cluster", "source": "vol", "target": "/c"},
])
def test_unchecked_mount_types_refused(paths: BoxPaths, project: Path, entry: dict) -> None:
    [finding] = service_findings({"volumes": [entry]}, project, paths, (project,))
    assert "use bind (inside the project), volume, tmpfs or image" in finding.advice


def test_image_mount_accepted(paths: BoxPaths, project: Path) -> None:
    entry = {"type": "image", "source": "alpine:3", "target": "/img"}
    assert _findings({"volumes": [entry]}, paths, project) == []


@pytest.mark.parametrize("entry", [
    "type=local,src=/etc", "Type=local,Dest=/var/tmp/x", "TYPE=LOCAL,src=/etc",
    '"type=local,dest=/x"', '"type=registry",dest=/x', "type=registry,dest=/x",
    "type=gha", "type=inline,src=/etc", "ref=x,dest=/y",
])
def test_cache_entries_parsed_like_buildx(project: Path, entry: str) -> None:
    [problem] = _problems({"context": ".", "cache_to": [entry]}, project)
    assert "type=registry,ref=<image> or type=inline" in problem


@pytest.mark.parametrize("entry", [
    "example.com/app:cache", "type=registry,ref=example.com/app:c,mode=max",
    "Type=Registry,Ref=example.com/app:c", "type=inline",
])
def test_registry_and_inline_caches_accepted(project: Path, entry: str) -> None:
    assert _problems({"context": ".", "cache_from": [entry]}, project) == []


@pytest.mark.parametrize("build", [
    {"context": "git@github.com:example/app.git"},
    {"context": "ssh://git@example.com/app.git"},
    {"context": ".", "additional_contexts": {"lib": "git@github.com:example/lib.git"}},
])
def test_ssh_git_contexts_refused(project: Path, build: dict) -> None:
    [problem] = _problems(build, project)
    assert "SSH agent" in problem and "https://" in problem
