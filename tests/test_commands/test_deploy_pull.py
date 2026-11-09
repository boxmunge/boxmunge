"""Which builds check the base images' registries (#124).

stage and prod-deploy build with --pull unless the operator passes
--no-pull, so a base image's fixes reach the next release. rollback does
not pull: it rebuilds the release it goes back to from the base images
the box has.
"""
from __future__ import annotations

import sys

import pytest

from boxmunge import cli
from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.rollback import run_rollback
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import add_project
from tests.bundle_helpers import place_bundle
from tests.stage_helpers import V1, V2, staging_docker_off
from tests.txn_helpers import docker_off


@pytest.fixture
def builds(monkeypatch) -> list[tuple[str, bool]]:
    """(component, pull) of every build that decides users."""
    seen: list[tuple[str, bool]] = []

    def prepare(paths, target, manifest, *, component, pull, rollback=False,
                refetch=frozenset()):
        seen.append((component, pull))
        return {}
    monkeypatch.setattr("boxmunge.commands.deploy_images.prepare_release_users", prepare)
    return seen


def _bundles(paths) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n"})
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})


@pytest.mark.parametrize("kwargs, pulled", [({}, True), ({"pull": False}, False)])
def test_prod_deploy_pulls_unless_told_not_to(paths, builds, kwargs, pulled) -> None:
    _bundles(paths)
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1, **kwargs) == 0
        assert run_deploy("myapp", paths, redeploy=True, **kwargs) == 0
    assert builds == [("deploy", pulled), ("deploy", pulled)]


@pytest.mark.parametrize("kwargs, pulled", [({}, True), ({"pull": False}, False)])
def test_stage_pulls_unless_told_not_to(paths, builds, kwargs, pulled) -> None:
    _bundles(paths)
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0
        assert run_stage("myapp", paths, ref=V2, **kwargs) == 0
    assert builds[-1] == ("stage", pulled)


def test_rollback_does_not_pull(paths, builds) -> None:
    _bundles(paths)
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0
        assert run_deploy("myapp", paths, ref=V2) == 0
        assert run_rollback("myapp", paths, yes=True) == 0
    assert builds[-1] == ("rollback", False)


def _main(argv: list[str], monkeypatch) -> int:
    monkeypatch.setattr(sys, "argv", ["boxmunge", *argv])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


@pytest.fixture
def runs(monkeypatch, paths: BoxPaths) -> list[tuple[str, dict]]:
    from boxmunge.commands import deploy, stage_cmd
    monkeypatch.setattr(BoxPaths.__init__, "__defaults__", (paths.root,))
    called: list[tuple[str, dict]] = []
    for module, name in [(deploy, "run_deploy"), (stage_cmd, "run_stage")]:
        monkeypatch.setattr(module, name,
                            lambda *a, _n=name, **k: called.append((_n, k)) or 0)
    return called


@pytest.mark.parametrize("argv, run, pulled", [
    (["prod-deploy", "myapp"], "run_deploy", True),
    (["prod-deploy", "myapp", "--no-pull"], "run_deploy", False),
    (["stage", "myapp"], "run_stage", True),
    (["stage", "myapp", "--no-pull"], "run_stage", False),
])
def test_no_pull_reaches_the_command(argv, run, pulled, runs, monkeypatch) -> None:
    assert _main(argv, monkeypatch) == 0
    assert runs == [(run, runs[0][1])] and runs[0][1]["pull"] is pulled


def test_abandon_takes_no_pull_option(runs, monkeypatch, capsys) -> None:
    assert _main(["prod-deploy", "myapp", "--abandon", "--no-pull"], monkeypatch) == 2
    assert runs == [] and "--abandon takes no other options" in capsys.readouterr().err


def test_the_mcp_tools_pass_no_pull_and_redeploy(monkeypatch) -> None:
    from boxmunge import mcp_tools
    from boxmunge.commands import deploy, stage_cmd
    from boxmunge.mcp_server import _TOOL_DEFS
    called: list[dict] = []
    monkeypatch.setattr(deploy, "run_deploy", lambda *a, **k: called.append(k) or 0)
    monkeypatch.setattr(stage_cmd, "run_stage", lambda *a, **k: called.append(k) or 0)
    monkeypatch.setattr(mcp_tools, "_get_paths", lambda: None)
    mcp_tools._tool_prod_deploy("myapp", no_pull=True, redeploy=True)
    mcp_tools._tool_stage("myapp", no_pull=True)
    mcp_tools._tool_stage("myapp")
    assert (called[0]["pull"], called[0]["redeploy"]) == (False, True)
    assert [c["pull"] for c in called[1:]] == [False, True]
    schemas = {t["name"]: t["inputSchema"]["properties"] for t in _TOOL_DEFS}
    assert {"no_pull", "redeploy"} <= set(schemas["prod_deploy"])
    assert "no_pull" in schemas["stage"]
