"""data chown holds the stopped service's restart policy until boxmunge starts it."""
from __future__ import annotations

import pytest

from boxmunge import chown_hold
from boxmunge.docker_containers import ProjectContainer
from boxmunge.docker_run import DockerError
from boxmunge.state import read_state, write_state


def _container(name: str, service: str, policies: dict, oneoff: bool = False
               ) -> ProjectContainer:
    return ProjectContainer(name=name, service=service, image_id="sha256:x", repo_digests=(),
                            running=False, health=None, oneoff=oneoff, exit_code=0,
                            restart_policy=policies[name])


@pytest.fixture
def docker(paths, monkeypatch):
    policies = {"shop-app-1": "always", "shop-app-2": "no", "shop-db-1": "unless-stopped",
                "shop-app-run-1": "no"}
    monkeypatch.setattr(chown_hold, "project_containers", lambda p: [
        _container("shop-app-1", "app", policies), _container("shop-app-2", "app", policies),
        _container("shop-db-1", "db", policies),
        _container("shop-app-run-1", "app", policies, oneoff=True)])
    monkeypatch.setattr("boxmunge.restart_hold.project_restart_policies",
                        lambda *, project_name: dict(policies))

    def set_policy(names, policy):
        for n in names:
            policies[n] = policy
    monkeypatch.setattr(chown_hold, "set_restart_policy", set_policy)
    monkeypatch.setattr("boxmunge.restart_hold.set_restart_policy", set_policy)
    paths.deploy_state.mkdir(parents=True, exist_ok=True)
    write_state(paths.project_deploy_state("shop"), {"current_ref": "shop-r1"})
    return policies


def test_hold_sets_only_the_services_containers_to_no_and_keeps_the_originals(
        paths, docker) -> None:
    assert chown_hold.hold(paths, "shop", "app") == ["shop-app-1", "shop-app-2"]
    assert docker == {"shop-app-1": "no", "shop-app-2": "no", "shop-db-1": "unless-stopped",
                      "shop-app-run-1": "no"}
    held = read_state(paths.project_deploy_state("shop"))[chown_hold.KEY]
    assert held == {"shop-app-1": {"service": "app", "policy": "always"},
                    "shop-app-2": {"service": "app", "policy": "no"}}


def test_a_second_hold_keeps_the_real_original(paths, docker) -> None:
    chown_hold.hold(paths, "shop", "app")
    chown_hold.hold(paths, "shop", "app")
    held = read_state(paths.project_deploy_state("shop"))[chown_hold.KEY]
    assert held["shop-app-1"]["policy"] == "always"


def test_a_start_of_the_service_gives_the_policy_back_and_clears_the_hold(
        paths, docker) -> None:
    chown_hold.hold(paths, "shop", "app")
    chown_hold.release(paths, "shop", ["db"])
    assert docker["shop-app-1"] == "no"
    chown_hold.release(paths, "shop", None)
    assert docker["shop-app-1"] == "always"
    assert chown_hold.KEY not in read_state(paths.project_deploy_state("shop"))


def test_a_failed_release_after_a_start_is_said_and_kept_for_the_next(
        paths, docker, monkeypatch, capsys) -> None:
    chown_hold.hold(paths, "shop", "app")

    def boom(*a, **k):
        raise DockerError("daemon not responding")
    monkeypatch.setattr("boxmunge.restart_hold.set_restart_policy", boom)
    chown_hold.release_after_start(paths, "shop", None, "container-update")
    assert "could not be given back" in capsys.readouterr().err
    assert chown_hold.KEY in read_state(paths.project_deploy_state("shop"))


def test_a_malformed_hold_record_fails_loudly(paths, docker) -> None:
    from boxmunge.state import StateError
    write_state(paths.project_deploy_state("shop"), {chown_hold.KEY: {"x": "always"}})
    with pytest.raises(StateError, match="not a restart hold"):
        chown_hold.release(paths, "shop", None)
