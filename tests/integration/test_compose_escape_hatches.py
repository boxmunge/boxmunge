"""Integration: Compose features that reach past the container, checked on
the model real `docker compose config` produces.

Each rejected case is a key the validator once let through: daemon socket
delegation, privileged lifecycle hooks, the cgroup namespace, build inputs
read from outside the project, build privileges, host-side providers, and
network modes naming another project's network. The accepted cases pin the
forms that stay allowed, so a fix cannot simply refuse every build.
"""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.paths import BoxPaths

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not on PATH"),
]


def _project(tmp_path: Path, svc: dict[str, Any], top: dict | None = None,
             files: dict[str, str] | None = None) -> tuple[BoxPaths, Path]:
    paths = BoxPaths(root=tmp_path / "bm")
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True)
    (project_dir / "Dockerfile").write_text("FROM alpine\n")
    for name, content in (files or {}).items():
        path = project_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    # A build service takes Compose's default image name: tagging `alpine`
    # would itself be refused (see the image-namespace cases).
    base = {} if "build" in svc else {"image": "alpine"}
    top = dict(top or {})
    doc: dict[str, Any] = {"services": {"web": {**base, **svc}, **top.pop("services", {})}}
    doc.update(top)
    compose = project_dir / "compose.yml"
    compose.write_text(yaml.safe_dump(doc))
    return paths, compose


def _validate(paths: BoxPaths, compose: Path, *, off: bool = False) -> None:
    validate_user_compose(
        compose, paths, project_name="myapp", off_services={"web"} if off else None,
    )


_BUILDABLE_SIBLING = {"services": {"db": {"build": "."}}}

REJECTED: dict[str, tuple[dict[str, Any], dict | None, str]] = {
    # 01: the daemon API socket, delegated without any volume entry.
    "use_api_socket": ({"use_api_socket": True}, None, "use_api_socket"),
    # 20: lifecycle hooks that run privileged.
    "post_start privileged": (
        {"post_start": [{"command": "id", "privileged": True}]}, None,
        r"post_start\[0\]\.privileged",
    ),
    "pre_stop privileged": (
        {"pre_stop": [{"command": ["id"], "privileged": True}]}, None,
        r"pre_stop\[0\]\.privileged",
    ),
    "post_start privileged as string": (
        {"post_start": [{"command": "id", "privileged": "true"}]}, None,
        r"post_start\[0\]\.privileged",
    ),
    "watch exec privileged": (
        {"develop": {"watch": [{"path": ".", "action": "sync+exec", "target": "/app",
                                "exec": {"command": "id", "privileged": True}}]}},
        None, r"develop\.watch\[0\]\.exec\.privileged",
    ),
    # 27: the Compose key is `cgroup`, not `cgroupns_mode`.
    "cgroup host": ({"cgroup": "host"}, None, "cgroup"),
    # Sweep: host devices by another name.
    "gpus": ({"gpus": "all"}, None, "gpus"),
    "reserved gpu devices": (
        {"deploy": {"resources": {"reservations": {"devices": [
            {"capabilities": ["gpu"]}]}}}},
        None, "deploy.resources.reservations.devices",
    ),
    # 04: build inputs that read outside the project.
    "additional context absolute host path": (
        {"build": {"context": ".", "additional_contexts": {"host": "/etc"}}}, None,
        "outside the project",
    ),
    "additional context relative escape": (
        {"build": {"context": ".", "additional_contexts": {"up": "../.."}}}, None,
        "outside the project",
    ),
    "additional context oci layout": (
        {"build": {"context": ".", "additional_contexts": {
            "oci": "oci-layout:///etc@sha256:" + "0" * 64}}},
        None, "oci-layout",
    ),
    "dockerfile absolute outside": (
        {"build": {"context": ".", "dockerfile": "/etc/shadow"}}, None,
        "build.dockerfile",
    ),
    "dockerfile relative escape": (
        {"build": {"context": ".", "dockerfile": "../../../etc/shadow"}}, None,
        "build.dockerfile",
    ),
    "dockerfile absolute with remote context": (
        {"build": {"context": "https://example.com/app.git#main",
                   "dockerfile": "/etc/shadow"}},
        None, "build.dockerfile",
    ),
    "main context unknown scheme": (
        {"build": {"context": "file:///etc"}}, None, "build context",
    ),
    "cache from local dir": (
        {"build": {"context": ".", "cache_from": ["type=local,src=/etc"]}}, None,
        "cache_from",
    ),
    "cache to local dir": (
        {"build": {"context": ".", "cache_to": ["type=local,dest=/var/tmp/x"]}}, None,
        "cache_to",
    ),
    "build ssh agent": ({"build": {"context": ".", "ssh": ["default"]}}, None, "build.ssh"),
    "build on named network": (
        {"build": {"context": ".", "network": "boxmunge-proxy"}}, None, "build.network",
    ),
    "build entitlements": (
        {"build": {"context": ".", "entitlements": ["network.host"]}}, None,
        "build.entitlements",
    ),
    "build privileged": ({"build": {"context": ".", "privileged": True}}, None,
                         "build.privileged"),
    # Sweep: a provider runs a host executable as the deploying user.
    "provider": ({"provider": {"type": "./evil.sh"}}, None, "provider"),
    # Sweep: network_mode accepts any Docker network name.
    "network_mode named network": (
        {"network_mode": "boxmunge-proxy"}, None, "network_mode",
    ),
    "network_mode other project": (
        {"network_mode": "projb_default"}, None, "network_mode",
    ),
    "network_mode default bridge": ({"network_mode": "bridge"}, None, "network_mode"),
    # pid/ipc joins outside the project are isolation, not hardening.
    "pid joins container": ({"pid": "container:projb-db-1"}, None, "pid"),
    "ipc joins container": ({"ipc": "container:projb-db-1"}, None, "ipc"),
    # A build may only tag names in the project's image namespace.
    "build tags a public image": (
        {"build": ".", "image": "postgres:16-alpine"}, None, "image namespace",
    ),
    "build tags the platform proxy image": (
        {"build": ".", "image": "caddy:2-alpine"}, None, "myapp-<name>",
    ),
    "build tags the platform system image": (
        {"build": ".", "image": "system-system"}, None, "image namespace",
    ),
    "build tag with registry host": (
        {"build": ".", "image": "registry.example.com/myapp-web"}, None, "no registry host",
    ),
    "extra build tag outside namespace": (
        {"build": {"context": ".", "tags": ["myapp-web:2", "redis:7"]}}, None, "'redis:7'",
    ),
}


@pytest.mark.parametrize("svc,top,match", REJECTED.values(), ids=REJECTED.keys())
def test_escape_hatch_rejected(tmp_path: Path, svc: dict, top: dict | None, match: str) -> None:
    paths, compose = _project(tmp_path, svc, top)
    with pytest.raises(ComposeSecurityError, match=match):
        _validate(paths, compose)


ISOLATION_EVEN_WHEN_OFF = [
    "additional context absolute host path", "dockerfile absolute outside",
    "cache from local dir", "build ssh agent", "build on named network", "provider",
    "network_mode other project", "pid joins container", "ipc joins container",
    "build tags a public image", "extra build tag outside namespace",
]


@pytest.mark.parametrize("case", ISOLATION_EVEN_WHEN_OFF)
def test_host_reach_not_relaxed_by_profile_off(tmp_path: Path, case: str) -> None:
    svc, top, match = REJECTED[case]
    paths, compose = _project(tmp_path, svc, top)
    with pytest.raises(ComposeSecurityError, match=match):
        _validate(paths, compose, off=True)


def test_models_rejected(tmp_path: Path) -> None:
    paths, compose = _project(
        tmp_path, {"models": ["llm"]}, {"models": {"llm": {"model": "ai/smollm2"}}},
    )
    with pytest.raises(ComposeSecurityError, match="models"):
        _validate(paths, compose)


def test_dockerfile_symlink_out_of_project_rejected(tmp_path: Path) -> None:
    paths, compose = _project(tmp_path, {"build": {"context": ".", "dockerfile": "Df"}})
    outside = tmp_path / "outside.Dockerfile"
    outside.write_text("FROM alpine\n")
    (compose.parent / "Df").symlink_to(outside)
    with pytest.raises(ComposeSecurityError, match="build.dockerfile"):
        _validate(paths, compose)


def test_label_file_outside_project_rejected(tmp_path: Path) -> None:
    paths, compose = _project(tmp_path, {"label_file": "../../outside.labels"})
    (tmp_path / "bm" / "outside.labels").write_text("a=b\n")
    with pytest.raises(ComposeSecurityError, match="label_file"):
        _validate(paths, compose)


ACCEPTED: dict[str, tuple[dict[str, Any], dict | None]] = {
    "hooks without privilege": (
        {"post_start": [{"command": "id", "user": "root"}],
         "pre_stop": [{"command": "id", "privileged": False}]}, None,
    ),
    "use_api_socket false": ({"use_api_socket": False}, None),
    "cgroup private": ({"cgroup": "private"}, None),
    "build inside project": (
        {"build": {"context": ".", "dockerfile": "Dockerfile",
                   "additional_contexts": {"assets": "./assets"}}}, None,
    ),
    "dockerfile in subdirectory": (
        {"build": {"context": ".", "dockerfile": "docker/web.Dockerfile"}}, None,
    ),
    "additional context image": (
        {"build": {"context": ".", "additional_contexts": {
            "base": "docker-image://alpine:3"}}}, None,
    ),
    "additional context service": (
        {"build": {"context": ".", "additional_contexts": {"db": "service:db"}}},
        _BUILDABLE_SIBLING,
    ),
    "additional context remote git": (
        {"build": {"context": ".", "additional_contexts": {
            "lib": "https://example.com/lib.git#v1"}}}, None,
    ),
    "remote context with in-repo dockerfile": (
        {"build": {"context": "https://example.com/app.git#main",
                   "dockerfile": "docker/Dockerfile"}}, None,
    ),
    "registry and inline cache": (
        {"build": {"context": ".", "cache_from": ["example.com/app:cache",
                                                   "type=registry,ref=example.com/app:c"],
                   "cache_to": ["type=inline"]}}, None,
    ),
    "build network none": ({"build": {"context": ".", "network": "none"}}, None),
    "network_mode none": ({"network_mode": "none"}, None),
    "network_mode sibling": ({"network_mode": "service:db"}, {"services": {"db": {"image": "x"}}}),
    "pid and ipc with sibling": (
        {"pid": "service:db", "ipc": "service:db"},
        {"services": {"db": {"image": "x", "ipc": "shareable"}}},
    ),
    "ipc private": ({"ipc": "private"}, None),
    "build with default image name": ({"build": "."}, None),
    "build with namespaced names": (
        {"build": {"context": ".", "tags": ["myapp_web:1", "myapp/web:2"]},
         "image": "myapp-web-local:latest"}, None,
    ),
}


@pytest.mark.parametrize("svc,top", ACCEPTED.values(), ids=ACCEPTED.keys())
def test_contained_forms_accepted(tmp_path: Path, svc: dict, top: dict | None) -> None:
    paths, compose = _project(tmp_path, svc, top, files={"assets/a.txt": "a\n",
                                                         "docker/web.Dockerfile": "FROM alpine\n"})
    _validate(paths, compose)


def test_api_socket_relaxed_with_warning_under_profile_off(tmp_path: Path) -> None:
    paths, compose = _project(tmp_path, {"use_api_socket": True})
    _validate(paths, compose, off=True)


def _with_projects(tmp_path: Path, *names: str) -> None:
    for name in names:
        (tmp_path / "bm" / "projects" / name).mkdir(parents=True)


def test_default_build_name_in_another_projects_namespace_refused(tmp_path: Path) -> None:
    """Compose's default name counts too: service bar-web builds myapp-bar-web."""
    paths, compose = _project(tmp_path, {"image": "alpine"},
                              {"services": {"bar-web": {"build": "."}}})
    _with_projects(tmp_path, "myapp-bar")
    with pytest.raises(ComposeSecurityError, match="service bar-web: .*'myapp-bar'"):
        _validate(paths, compose)


@pytest.mark.parametrize("svc,others,match", [
    # foo-bar-web is in both namespaces; the longer project name owns it.
    ({"build": ".", "image": "myapp-bar-web"}, ["myapp-bar"], "'myapp-bar'"),
    # The reverse: running an image another project builds.
    ({"image": "projb-web:latest"}, ["projb"], "Compose could run that project"),
    ({"image": "docker.io/library/projb-web"}, ["projb"], "'projb'"),
    ({"image": "system-system"}, [], "'system'"),
])
def test_image_namespace_of_other_projects_refused(
    tmp_path: Path, svc: dict, others: list[str], match: str,
) -> None:
    paths, compose = _project(tmp_path, svc)
    _with_projects(tmp_path, *others)
    with pytest.raises(ComposeSecurityError, match=match):
        _validate(paths, compose, off=True)


def test_public_and_own_images_run_alongside_other_projects(tmp_path: Path) -> None:
    paths, compose = _project(
        tmp_path, {"image": "myapp-worker"},
        {"services": {"db": {"image": "postgres:16-alpine"},
                      "cache": {"image": "ghcr.io/projb/cache:1"}}},
    )
    _with_projects(tmp_path, "projb", "postgres-tools")
    _validate(paths, compose)
