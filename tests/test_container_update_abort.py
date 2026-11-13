# SPDX-License-Identifier: Apache-2.0
"""An update that pulls and then stops before its recreate puts every image
tag back (audit F01), so the next restart of any kind runs the images the
project ran before, not the ones the update refused."""
from __future__ import annotations

import pytest

from boxmunge import container_update as cu
from boxmunge import container_update_tags, user_drift
from boxmunge.commands.container_update_cmd import _dry_run_target, update_project
from boxmunge.compose_guard import ComposeRefused
from boxmunge.container_update_targets import UpdateTarget
from boxmunge.deployed_inventory import DeployedService
from boxmunge.docker import DockerError
from boxmunge.docker_containers import ImageFacts, LocalImage, ProjectContainer
from boxmunge.pause import mark_pause_complete, write_paused_state
from boxmunge.run_as import RunAsError, ServiceUser, write_users
from tests.deploy_helpers import mark_deployed
from tests.test_container_update import _NEW, _OLD, FakeDocker, _write_project

_SERVICES = {"web": "nginx:1.25", "db": "postgres:17"}
_ALL_OLD = {"web": _OLD, "db": _OLD}


def _compose(paths, name, services):
    (paths.project_dir(name) / "compose.yml").write_text("services:\n" + "".join(
        f"  {svc}:\n    image: {ref}\n" for svc, ref in services.items()))
    mark_deployed(paths, name)


def _project(paths, monkeypatch, fake_containers, name="shop"):
    """A project with a backup whose two images both have a newer upstream."""
    _write_project(paths, name, with_backup=True)
    _compose(paths, name, _SERVICES)
    docker = FakeDocker(monkeypatch, fake_containers, name, dict(_SERVICES))
    docker.pulled = {ref: _NEW for ref in _SERVICES.values()}
    write_users(paths, name, {svc: ServiceUser("10001:10001", "default", "")
                              for svc in _SERVICES})
    monkeypatch.setattr(user_drift, "tag_image", docker._tag)
    monkeypatch.setattr(user_drift, "notify", lambda *a, **kw: True)
    monkeypatch.setattr(cu, "backup_locked", lambda *a, **kw: 0)
    target = UpdateTarget(name=name, project_dir=paths.project_dir(name),
                          compose_files=["compose.yml"], strategy="leave_broken",
                          has_backup=True)
    return docker, target


def _restart(docker) -> dict[str, str]:
    """A plain restart recreates from the local tags: {service: image it runs}."""
    docker._recreate()
    return {c.service: c.image_id for c in docker.containers(docker.project)}


def _raiser(error):
    def raises(*args, **kwargs):
        raise error
    return raises


def _docker_tag_fails_for_db(monkeypatch, docker):
    def tag(source, ref):
        if ref == "postgres:17":
            raise DockerError("no space left on device")
        docker._tag(source, ref)
    monkeypatch.setattr(container_update_tags, "tag_image", tag)


def _backup_fails(paths, monkeypatch, docker):
    monkeypatch.setattr(cu, "backup_locked", lambda *a, **kw: 1)


def _compose_refuses(paths, monkeypatch, docker):
    monkeypatch.setattr(cu, "compose_up_checked", _raiser(ComposeRefused("a mount changed")))


def _pull_fails_partway(paths, monkeypatch, docker):
    def pull(*args, **kwargs):
        docker.tags["postgres:17"] = _NEW
        raise DockerError("nginx:1.25: manifest unknown")
    monkeypatch.setattr(cu, "compose_pull", pull)
    monkeypatch.setattr("boxmunge.docker.compose_pull", pull)  # the dry run's


def _inspect_fails_after_pull(paths, monkeypatch, docker):
    state = {"fail": False}

    def pull(*args, **kwargs):
        docker._pull()
        state["fail"] = True

    def local_image(ref):
        if state["fail"] and ref == "nginx:1.25":
            state["fail"] = False
            raise DockerError("docker image inspect nginx:1.25 failed: daemon busy")
        return docker._local_image(ref)
    monkeypatch.setattr(cu, "compose_pull", pull)
    monkeypatch.setattr("boxmunge.docker_containers.local_image", local_image)


def _user_check_fails(paths, monkeypatch, docker):
    monkeypatch.setattr(cu, "guard_pull", _raiser(RunAsError("users record unreadable")))


def _user_drifts(paths, monkeypatch, docker):
    """db runs as its image's own user, and the new image's user differs."""
    write_users(paths, docker.project, {"web": ServiceUser("10001:10001", "default", ""),
                                        "db": ServiceUser(None, "manifest", "")})
    monkeypatch.setattr("boxmunge.docker_containers.image_facts",
                        lambda ref: ImageFacts(_NEW, "postgres", ()))


@pytest.mark.parametrize("abort, reason", [
    (_pull_fails_partway, "pull_failed: "),
    (_inspect_fails_after_pull, "inventory_failed: "),
    (_user_check_fails, "inventory_failed: "),
    (_user_drifts, "user_changed: db"),
    (_backup_fails, "backup_failed"),
    (_compose_refuses, "refused: "),
])
def test_abort_after_pull_puts_the_tags_back(
        abort, reason, paths, monkeypatch, fake_containers) -> None:
    docker, target = _project(paths, monkeypatch, fake_containers)
    abort(paths, monkeypatch, docker)

    result = cu.update_target_locked(paths, target)

    assert result["status"] == "failed" and result["reason"].startswith(reason), result
    assert result["tags_not_restored"] == [] and "tag_restore_failed" not in result["reason"]
    assert docker.ups == 0
    assert docker.tags == {"nginx:1.25": _OLD, "postgres:17": _OLD}
    assert _restart(docker) == _ALL_OLD


def test_a_tag_that_cannot_be_put_back_is_reported(paths, monkeypatch, fake_containers) -> None:
    docker, target = _project(paths, monkeypatch, fake_containers)
    _backup_fails(paths, monkeypatch, docker)
    _docker_tag_fails_for_db(monkeypatch, docker)
    logged = []
    monkeypatch.setattr(container_update_tags, "log_error",
                        lambda component, message, *a, **kw: logged.append(message))

    result = cu.update_target_locked(paths, target)

    assert result["status"] == "failed" and result["tags_not_restored"] == ["postgres:17"]
    assert result["reason"].startswith("backup_failed; tag_restore_failed: postgres:17")
    assert "no space left on device" in result["reason"]
    assert f"docker tag {_OLD} postgres:17" in result["reason"]
    assert len(logged) == 1 and "postgres:17" in logged[0]
    # The report is true: the restart it warns about runs the pulled image.
    assert _restart(docker) == {"web": _OLD, "db": _NEW}


def test_restore_moves_a_shared_tag_for_every_project(paths, monkeypatch, fake_containers) -> None:
    """Known residual until image identities are per project (0.12): a tag is
    one host-wide pointer, so project A's abort points it back for project B
    too. B had already updated; its next recreate runs the older image, and
    B's next update run brings it forward again."""
    _write_project(paths, "other")
    _compose(paths, "other", {"db": "postgres:17"})
    b = FakeDocker(monkeypatch, fake_containers, "other", {"db": "postgres:17"})
    a, target = _project(paths, monkeypatch, fake_containers)
    b.tags = a.tags
    a.tags["postgres:17"] = _NEW  # B's own update pulled it ...
    assert _restart(b) == {"db": _NEW}  # ... and recreated B on it
    _backup_fails(paths, monkeypatch, a)

    result = cu.update_target_locked(paths, target)

    assert result["reason"] == "backup_failed"
    assert _restart(a) == _ALL_OLD
    assert _restart(b) == {"db": _OLD}
    b_target = UpdateTarget(name="other", project_dir=paths.project_dir("other"),
                            compose_files=["compose.yml"], strategy="leave_broken",
                            has_backup=False)
    write_users(paths, "other", {"db": ServiceUser("10001:10001", "default", "")})
    monkeypatch.setattr("boxmunge.compose_guard.compose_up", b._up)
    b.pulled = {"postgres:17": _NEW}
    monkeypatch.setattr(cu, "compose_pull", b._pull)
    assert cu.update_target_locked(paths, b_target)["status"] == "succeeded"
    assert {c.image_id for c in fake_containers("other")} == {_NEW}


def _service(name, ref, image_id):
    container = ProjectContainer(
        name=f"shop-{name}-1", service=name, image_id=image_id, repo_digests=(),
        running=True, health=None, oneoff=False, exit_code=None,
        restart_policy="unless-stopped")
    return DeployedService(name, ref, False, True, (container,)), container


def test_services_sharing_a_tag_at_different_images_are_reported(paths, monkeypatch) -> None:
    """There is no one image to point the tag back at; say so, don't pick."""
    other = "sha256:" + "2" * 64
    (web, web_c), (job, job_c) = _service("web", "app:1", _OLD), _service("job", "app:1", other)
    monkeypatch.setattr("boxmunge.docker_containers.local_image",
                        lambda ref: LocalImage(_NEW, ()))
    monkeypatch.setattr(container_update_tags, "tag_image",
                        _raiser(AssertionError("must not pick one")))

    stuck = container_update_tags.restore_tags(
        paths, "shop", {"web": web, "job": job}, {"web": web_c, "job": job_c})

    assert list(stuck) == ["app:1"] and "Redeploy the project" in stuck["app:1"]


def test_a_digest_reference_is_never_retagged(paths, monkeypatch) -> None:
    ref = "postgres@sha256:" + "9" * 64
    db, db_c = _service("db", ref, _OLD)
    monkeypatch.setattr("boxmunge.docker_containers.local_image",
                        _raiser(AssertionError("nothing to inspect")))

    assert container_update_tags.restore_tags(paths, "shop", {"db": db}, {"db": db_c}) == {}


# --- The dry run pulls too (and the nightly pre-fetch of a paused project is one) ---

def test_dry_run_reports_the_change_and_puts_the_tags_back(
        paths, monkeypatch, fake_containers) -> None:
    docker, target = _project(paths, monkeypatch, fake_containers)

    result = _dry_run_target(paths, target)

    assert result["status"] == "would_change" and sorted(result["current_digests"]) == ["db", "web"]
    assert result["tags_not_restored"] == []
    assert docker.tags == {"nginx:1.25": _OLD, "postgres:17": _OLD}
    assert _restart(docker) == _ALL_OLD


def test_failed_dry_run_puts_the_tags_back(paths, monkeypatch, fake_containers) -> None:
    docker, target = _project(paths, monkeypatch, fake_containers)
    _pull_fails_partway(paths, monkeypatch, docker)

    result = _dry_run_target(paths, target)

    assert result["status"] == "failed" and result["reason"].startswith("pull_failed: ")
    assert result["tags_not_restored"] == [] and _restart(docker) == _ALL_OLD


def test_dry_run_with_a_tag_it_cannot_put_back_fails(paths, monkeypatch, fake_containers) -> None:
    docker, target = _project(paths, monkeypatch, fake_containers)
    _docker_tag_fails_for_db(monkeypatch, docker)

    result = _dry_run_target(paths, target)

    assert result["status"] == "failed" and result["tags_not_restored"] == ["postgres:17"]
    assert result["reason"].startswith("tag_restore_failed: postgres:17")
    assert f"docker tag {_OLD} postgres:17" in result["reason"]


def _paused(paths, monkeypatch, fake_containers):
    """The project, paused: its containers are stopped, on the old images."""
    docker, target = _project(paths, monkeypatch, fake_containers)
    fake_containers.remove(docker.project)
    for svc in _SERVICES:
        fake_containers.run(docker.project, svc, _OLD, running=False, exit_code=0)
    write_paused_state(docker.project, paths)
    mark_pause_complete(docker.project, paths)
    return docker, target


def test_prefetch_of_a_paused_project_leaves_its_tags_for_the_resume(
        paths, monkeypatch, fake_containers) -> None:
    """The nightly run pre-fetches a paused project's images and reports
    them as pending. A resume that does not pull recreates from local tags:
    it must start the images the project was paused on."""
    docker, target = _paused(paths, monkeypatch, fake_containers)

    result = update_project(paths, target, dry_run=False)

    assert result["status"] == "paused" and result["pending_services"] == ["db", "web"]
    assert docker.ups == 0 and docker.tags == {"nginx:1.25": _OLD, "postgres:17": _OLD}
    assert _restart(docker) == _ALL_OLD


def test_prefetch_that_cannot_put_a_tag_back_is_a_failure_not_a_skip(
        paths, monkeypatch, fake_containers) -> None:
    docker, target = _paused(paths, monkeypatch, fake_containers)
    _docker_tag_fails_for_db(monkeypatch, docker)

    result = update_project(paths, target, dry_run=False)

    assert result["status"] == "failed" and result["tags_not_restored"] == ["postgres:17"]
    assert f"docker tag {_OLD} postgres:17" in result["reason"]
