# SPDX-License-Identifier: Apache-2.0
"""Built images carry the platform's name end to end, with real Docker.

The overlay names a build service's image boxmunge.invalid/<compose-project>/
<service>. This walks one project through what an existing deployment sees:
it starts under Compose's old default name, regenerates its overlay (as an
upgrade does), comes back up under the new name, is staged, scanned and
container-updated, and is finally deleted, which removes its built images.
"""
from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path

import pytest
import yaml

from boxmunge.commands.project_delete_cmd import _teardown
from boxmunge.commands.security_scan_inputs import identify_images, identify_startup_images
from boxmunge.compose import (
    generate_staging_compose_base,
    generate_staging_compose_override,
    load_user_compose,
    prepare_compose_override,
)
from boxmunge.compose_validate import validate_user_compose
from boxmunge.commands.container_update_cmd import update_project
from boxmunge.container_update_targets import UpdateTarget
from boxmunge.deployed_inventory import load_deployed_inventory
from boxmunge.docker import compose_up
from boxmunge.docker_containers import local_image
from boxmunge.paths import BoxPaths
from tests.integration.conftest import skip_no_docker

pytestmark = [pytest.mark.integration, skip_no_docker]

_REGISTRY_IMAGE = "alpine:3.20"


def _container_image(container: str) -> str:
    out = subprocess.run(["docker", "inspect", "--format", "{{.Config.Image}}", container],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


def local_image_id(ref: str) -> str | None:
    image = local_image(ref)
    return image.image_ref if image else None


def _images(prefix: str) -> list[str]:
    out = subprocess.run(
        ["docker", "image", "ls", "--format", "{{.Repository}}",
         "--filter", f"reference={prefix}*"],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.split()


@pytest.fixture
def project(tmp_path: Path):
    name = f"bmimg-{uuid.uuid4().hex[:8]}"
    paths = BoxPaths(root=tmp_path / "bm")
    for d in (paths.state, paths.deploy_state, paths.log_file.parent):
        d.mkdir(parents=True, exist_ok=True)
    project_dir = paths.project_dir(name)
    project_dir.mkdir(parents=True)
    (project_dir / "Dockerfile").write_text(
        f'FROM {_REGISTRY_IMAGE}\nRUN echo {name} > /built\nCMD ["sleep", "3600"]\n')
    (project_dir / "compose.yml").write_text(yaml.safe_dump({"services": {
        "web": {"build": ".", "image": f"{name}-custom"},
        "cache": {"image": _REGISTRY_IMAGE, "command": ["sleep", "3600"]},
    }}))
    manifest = {"project": name, "hosts": [f"{name}.example.com"],
                "services": {"web": {"port": 8080}}}
    yield paths, name, project_dir, manifest
    _teardown(name, paths)
    subprocess.run(["docker", "image", "rm", "-f", f"{name}-web", f"{name}-custom"],
                   capture_output=True, check=False)


def test_deploy_stage_update_and_delete_use_platform_names(project) -> None:
    paths, name, project_dir, manifest = project
    validate_user_compose(project_dir / "compose.yml", paths, project_name=name,
                          manifest_services=manifest["services"])

    # A deployment from before the rename: Compose tagged the build with the
    # service's own image: name (and, without one, `<project>-<service>`).
    compose_up(project_dir, project_name=name)
    assert _container_image(f"{name}-web-1") == f"{name}-custom"
    subprocess.run(["docker", "tag", f"{name}-custom", f"{name}-web"], check=True)

    # Regenerating the overlay (deploy, upgrade) drops every name the
    # labels prove this project built; the running container keeps its image.
    prepare_compose_override(paths, manifest, release_root=project_dir)
    assert local_image_id(f"{name}-web") is None
    assert local_image_id(f"{name}-custom") is None
    assert local_image_id(_REGISTRY_IMAGE) is not None
    assert subprocess.run(["docker", "inspect", f"{name}-web-1"],
                          capture_output=True, check=False).returncode == 0

    # The next up recreates the service under the platform's name.
    files = ["compose.yml", "compose.boxmunge.yml"]
    compose_up(project_dir, compose_files=files, project_name=name)
    built = f"boxmunge.invalid/{name}/web"
    assert _container_image(f"{name}-web-1") == built

    # The scanner sees the built image by its new name, from the container
    # and, once that is gone, as the image `up` would start.
    deployed = load_deployed_inventory(project_dir, files, name)
    targets = {t.service: t.image_ref for t in identify_images(manifest, deployed).targets}
    assert targets["web"] == local_image_id(built)
    subprocess.run(["docker", "rm", "-f", f"{name}-web-1"], capture_output=True, check=True)
    deployed = load_deployed_inventory(project_dir, files, name)
    startup = identify_startup_images(manifest, deployed, "paused")
    assert local_image_id(built) in {t.image_ref for t in startup.targets if t.service == "web"}
    compose_up(project_dir, compose_files=files, project_name=name)

    # container-update pulls only the registry image, not the built one.
    result = update_project(paths, UpdateTarget(
        name=name, project_dir=project_dir, compose_files=files,
        strategy="leave_broken", has_backup=False,
    ), dry_run=False)
    assert result["status"] == "no_change", result
    assert _container_image(f"{name}-web-1") == built

    # Staging builds under its own name and leaves production's alone.
    user = load_user_compose(project_dir / "compose.yml", name)
    (project_dir / "compose.boxmunge-staging.yml").write_text(
        generate_staging_compose_override(manifest, user_compose=user))
    (project_dir / "compose.staging-base.yml").write_text(
        generate_staging_compose_base(project_dir / "compose.yml"))
    compose_up(project_dir, compose_files=["compose.staging-base.yml",
                                           "compose.boxmunge-staging.yml"],
               project_name=f"{name}-staging")
    assert _container_image(f"{name}-staging-web-1") == f"boxmunge.invalid/{name}-staging/web"
    assert local_image_id(built) is not None

    # Delete removes exactly this project's built images.
    assert _teardown(name, paths) == []
    assert _images(f"boxmunge.invalid/{name}/") == []
    assert _images(f"boxmunge.invalid/{name}-staging/") == []
    assert local_image_id(_REGISTRY_IMAGE) is not None


def test_own_build_run_by_another_service_is_not_pulled(project) -> None:
    """A worker running the web build by its platform name: no registry
    serves boxmunge.invalid/, so pulling it would fail the whole update."""
    paths, name, project_dir, manifest = project
    compose = yaml.safe_load((project_dir / "compose.yml").read_text())
    compose["services"]["worker"] = {"image": f"boxmunge.invalid/{name}/web",
                                     "depends_on": ["web"]}
    (project_dir / "compose.yml").write_text(yaml.safe_dump(compose))
    validate_user_compose(project_dir / "compose.yml", paths, project_name=name)
    prepare_compose_override(paths, manifest, release_root=project_dir)
    files = ["compose.yml", "compose.boxmunge.yml"]
    compose_up(project_dir, compose_files=files, project_name=name)
    result = update_project(paths, UpdateTarget(
        name=name, project_dir=project_dir, compose_files=files,
        strategy="leave_broken", has_backup=False,
    ), dry_run=False)
    assert result["status"] == "no_change", result


def test_untagging_leaves_a_prefix_sharing_projects_image_alone(tmp_path: Path) -> None:
    """`foo`'s service `bar-web` and `foo-bar`'s service `web` share the old
    default name foo-bar-web; only Compose's labels tell them apart."""
    suffix = uuid.uuid4().hex[:6]
    foo, foo_bar = f"bmfoo{suffix}", f"bmfoo{suffix}-bar"
    paths = BoxPaths(root=tmp_path / "bm")
    for proj, service in ((foo, "bar-web"), (foo_bar, "web")):
        pdir = paths.project_dir(proj)
        pdir.mkdir(parents=True)
        (pdir / "Dockerfile").write_text(f"FROM {_REGISTRY_IMAGE}\nRUN echo {proj} > /who\n")
        (pdir / "compose.yml").write_text(yaml.safe_dump(
            {"services": {service: {"build": ".", "command": ["sleep", "3600"]}}}))
    try:
        # foo-bar's build carries the shared old name.
        subprocess.run(["docker", "compose", "-p", foo_bar, "build", "-q"],
                       cwd=paths.project_dir(foo_bar), check=True, capture_output=True)
        shared = f"{foo_bar}-web"
        assert local_image_id(shared) is not None
        manifest = {"project": foo, "hosts": ["foo.example.com"], "services": {}}
        prepare_compose_override(paths, manifest, release_root=paths.project_dir(foo))
        assert local_image_id(shared) is not None
    finally:
        subprocess.run(["docker", "image", "rm", "-f", f"{foo_bar}-web"],
                       capture_output=True, check=False)


def test_profiled_service_is_hardened_in_the_overlay(project) -> None:
    """`restore` starts a backup service by name, activating its profile, so
    the overlay must cover services outside the default profile."""
    paths, name, project_dir, manifest = project
    compose = yaml.safe_load((project_dir / "compose.yml").read_text())
    compose["services"]["ops"] = {"image": _REGISTRY_IMAGE, "profiles": ["ops"]}
    (project_dir / "compose.yml").write_text(yaml.safe_dump(compose))
    prepare_compose_override(paths, manifest, release_root=project_dir)
    overlay = yaml.safe_load((project_dir / "compose.boxmunge.yml").read_text())
    assert "no-new-privileges:true" in overlay["services"]["ops"]["security_opt"]
    out = subprocess.run(
        ["docker", "compose", "-p", name, "-f", "compose.yml", "-f", "compose.boxmunge.yml",
         "--profile", "ops", "config", "--format", "json"],
        cwd=project_dir, capture_output=True, text=True, check=True,
    )
    assert "SYS_PTRACE" in json.loads(out.stdout)["services"]["ops"]["cap_drop"]


def test_old_names_of_a_removed_service_are_untagged(project) -> None:
    """A service since removed or renamed loses its old name too, when its
    image's Compose project label says it is this project's build."""
    paths, name, project_dir, manifest = project
    compose = yaml.safe_load((project_dir / "compose.yml").read_text())
    # The label Compose puts on its builds, written out: Compose 2.38 builds
    # without it, and then nothing proves a removed service's image ours.
    compose["services"]["old"] = {
        "build": {"context": ".", "labels": {"com.docker.compose.project": name}},
        "command": ["sleep", "3600"],
    }
    (project_dir / "compose.yml").write_text(yaml.safe_dump(compose))
    # Deployed, then dropped from compose.yml: its container lingers until
    # the next up removes orphans, so the regenerated overlay comes first.
    compose_up(project_dir, project_name=name)
    assert local_image_id(f"{name}-old") is not None
    del compose["services"]["old"]
    (project_dir / "compose.yml").write_text(yaml.safe_dump(compose))
    prepare_compose_override(paths, manifest, release_root=project_dir)
    assert local_image_id(f"{name}-old") is None


def test_untag_keeps_an_image_another_projects_container_uses(project) -> None:
    """Labels say this project built it, but another project's container
    runs it: untagging would leave that project unable to recreate it."""
    paths, name, project_dir, manifest = project
    compose_up(project_dir, project_name=name)
    other = f"{name}x-other-1"
    subprocess.run(["docker", "create", "--name", other,
                    "--label", f"com.docker.compose.project={name}x",
                    f"{name}-custom"], check=True, capture_output=True)
    try:
        prepare_compose_override(paths, manifest, release_root=project_dir)
        assert local_image_id(f"{name}-custom") is not None
    finally:
        subprocess.run(["docker", "rm", "-f", other], capture_output=True, check=False)
    prepare_compose_override(paths, manifest, release_root=project_dir)
    assert local_image_id(f"{name}-custom") is None


@pytest.fixture
def local_registry():
    """A throwaway registry, so a local build gets RepoDigests by a push, as
    every local build has under the containerd image store."""
    port = 25000 + uuid.uuid4().int % 5000
    cname = f"bmreg-{uuid.uuid4().hex[:8]}"
    subprocess.run(["docker", "run", "-d", "--name", cname, "-p", f"127.0.0.1:{port}:5000",
                    "registry:2"], check=True, capture_output=True)
    yield f"localhost:{port}"
    subprocess.run(["docker", "rm", "-f", cname], capture_output=True, check=False)


def test_untag_does_not_depend_on_repo_digests(project, local_registry) -> None:
    paths, name, project_dir, manifest = project
    compose_up(project_dir, project_name=name)
    pushed = f"{local_registry}/{name}-custom:latest"
    subprocess.run(["docker", "tag", f"{name}-custom", pushed], check=True)
    for attempt in range(10):
        if subprocess.run(["docker", "push", pushed], capture_output=True).returncode == 0:
            break
        subprocess.run(["sleep", "1"])
    digests = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{len .RepoDigests}}", f"{name}-custom"],
        capture_output=True, text=True, check=True).stdout.strip()
    assert digests != "0"
    prepare_compose_override(paths, manifest, release_root=project_dir)
    assert local_image_id(f"{name}-custom") is None
    assert local_image_id(pushed) is None


def test_unlabelled_build_is_owned_through_the_projects_container(project) -> None:
    """Compose 2.38 builds images without labels. The image a container of
    one of this project's build services runs is still recognised as its
    build, whatever the image store."""
    paths, name, project_dir, manifest = project
    compose = yaml.safe_load((project_dir / "compose.yml").read_text())
    compose["services"]["plainsvc"] = {"build": "."}
    (project_dir / "compose.yml").write_text(yaml.safe_dump(compose))
    plain = f"{name}-plainsvc"
    subprocess.run(["docker", "build", "-q", "-t", plain, str(project_dir)],
                   check=True, capture_output=True)
    labels = subprocess.run(["docker", "image", "inspect", "--format", "{{json .Config.Labels}}",
                             plain], capture_output=True, text=True, check=True).stdout
    assert "com.docker.compose.project" not in labels
    container = f"{name}-plainsvc-1"
    subprocess.run(["docker", "create", "--name", container,
                    "--label", f"com.docker.compose.project={name}",
                    "--label", "com.docker.compose.service=plainsvc", plain],
                   check=True, capture_output=True)
    try:
        prepare_compose_override(paths, manifest, release_root=project_dir)
        assert local_image_id(plain) is None
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, check=False)


def _labelled_container(name: str, project: str, service: str, image: str) -> None:
    subprocess.run(["docker", "create", "--name", name,
                    "--label", f"com.docker.compose.project={project}",
                    "--label", f"com.docker.compose.service={service}", image],
                   check=True, capture_output=True)


def test_unlabelled_build_of_a_bare_from_keeps_the_base_images_name(project) -> None:
    """A Dockerfile that is just `FROM <base>`, built by Compose 2.38 (no
    labels), is the base image itself; only this project's name for it goes."""
    paths, name, project_dir, manifest = project
    compose = yaml.safe_load((project_dir / "compose.yml").read_text())
    compose["services"]["thin"] = {"build": "."}
    (project_dir / "compose.yml").write_text(yaml.safe_dump(compose))
    # A base image of its own, so no other container on the host uses it.
    base = f"{name}-base:1"
    subprocess.run(["docker", "build", "-q", "-t", base, str(project_dir)],
                   check=True, capture_output=True)
    subprocess.run(["docker", "tag", base, f"{name}-thin"], check=True)
    container = f"{name}-thin-1"
    _labelled_container(container, name, "thin", f"{name}-thin")
    try:
        prepare_compose_override(paths, manifest, release_root=project_dir)
        assert local_image_id(f"{name}-thin") is None
        assert local_image_id(base) is not None
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, check=False)
        subprocess.run(["docker", "image", "rm", "-f", base], capture_output=True, check=False)


def test_own_image_only_service_still_on_the_old_name_protects_it(project) -> None:
    """A worker running the web build by its old name, not yet recreated."""
    paths, name, project_dir, manifest = project
    compose_up(project_dir, project_name=name)
    compose = yaml.safe_load((project_dir / "compose.yml").read_text())
    compose["services"]["worker"] = {"image": f"{name}-custom"}
    (project_dir / "compose.yml").write_text(yaml.safe_dump(compose))
    worker = f"{name}-worker-1"
    _labelled_container(worker, name, "worker", f"{name}-custom")
    try:
        prepare_compose_override(paths, manifest, release_root=project_dir)
        assert local_image_id(f"{name}-custom") is not None
    finally:
        subprocess.run(["docker", "rm", "-f", worker], capture_output=True, check=False)
