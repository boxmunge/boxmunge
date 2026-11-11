# SPDX-License-Identifier: Apache-2.0
"""A start runs on what its check resolved, and only a check can say so."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

import boxmunge
from boxmunge import checked_start
from boxmunge.checked_start import CheckedStart
from boxmunge.compose_guard import ComposeRefused, check_start, compose_up_checked
from tests.deploy_helpers import mark_deployed
from tests.docker_call_counter import docker_calls

FILES = ["compose.yml"]


@pytest.fixture
def project(paths):
    project_dir = paths.project_dir("myapp")
    (project_dir / "data").mkdir(parents=True)
    (project_dir / "manifest.yml").write_text(
        "id: 01TEST\nproject: myapp\nsource: bundle\nhosts:\n  - myapp.example.com\n"
        "services:\n  web:\n    port: 8080\n    routes:\n      - path: /\n")
    (project_dir / "compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n    volumes:\n      - ./data:/data\n")
    mark_deployed(paths, "myapp")
    return paths


def test_the_check_returns_the_model_it_resolved_and_what_it_read(project) -> None:
    checked = check_start(project, "myapp", component="test", compose_files=FILES)
    assert isinstance(checked, CheckedStart)
    assert checked.model["services"]["web"]["image"] == "nginx"
    assert (checked.project_name, checked.staging, checked.compose_files) == (
        "myapp", False, ("compose.yml",))
    assert checked.sources == {"data"} and checked.kinds["data"] == "dir"
    assert checked.control["compose.yml"] and checked.control["manifest.yml"]


def test_a_recording_check_returns_what_it_recorded(project) -> None:
    project.project_bind_record("myapp").unlink()
    checked = check_start(project, "myapp", component="test", compose_files=FILES,
                          record=True)
    assert checked.kinds == {"data": "dir"}
    assert checked.control["compose.yml"]


def test_nothing_but_a_check_can_build_one(project) -> None:
    checked = check_start(project, "myapp", component="test", compose_files=FILES)
    fields = {name: getattr(checked, name) for name in CheckedStart.__dataclass_fields__}
    with pytest.raises(TypeError, match="compose_guard.check_start"):
        CheckedStart(**{**fields, "by": object()})


def test_only_compose_guard_issues_one() -> None:
    """`issue` is the one way past the constructor: no other module of
    boxmunge may call it, or reach for the token it holds."""
    src = Path(boxmunge.__file__).parent
    reaching = re.compile(r"\bissue\(|_BY_A_CHECK|\bCheckedStart\(")
    found = sorted(str(path.relative_to(src)) for path in src.rglob("*.py")
                   if path.name != "checked_start.py" and "checked_start" in path.read_text()
                   and reaching.search(path.read_text()))
    assert found == ["compose_guard.py"]
    assert len(re.findall(r"checked_start\.issue\(", (src / "compose_guard.py").read_text())) == 2
    assert checked_start.issue.__doc__


# -- a start on the check its operation already ran ---------------------------

def _start(paths, earlier, **kwargs):
    with docker_calls() as seen:
        compose_up_checked(paths, "myapp", component="test", compose_files=FILES,
                           earlier=earlier, **kwargs)
    return seen


def test_a_start_on_an_earlier_check_resolves_nothing_while_nothing_changed(project) -> None:
    """resume and restore check before they touch a container and start
    later. The files that check read still hash as it read them, and its
    bind sources are what it saw, so the model is the one it resolved."""
    checked = check_start(project, "myapp", component="test", compose_files=FILES)
    seen = _start(project, checked)
    assert seen.compose_config == [] and seen.docker_info == []
    assert seen.other_matching("compose", "up")
    # The mounts the project's containers hold are still asked for.
    assert seen.other_matching("query container_bind_sources")


@pytest.mark.parametrize("change, refusal", [
    (lambda d: (d / "compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n    privileged: true\n"), "privileged"),
    (lambda d: (d / "manifest.yml").write_text((d / "manifest.yml").read_text() + "# x\n"),
     "control file manifest.yml changed"),
    (lambda d: ((d / "data").rmdir(), (d / "data").symlink_to("/etc")),
     "protected host path"),
    (lambda d: (d / ".env").write_text("TAG=evil\n"), "control file .env"),
])
def test_a_change_since_the_check_is_checked_in_full_and_refused(
        project, change, refusal) -> None:
    """Anything not as the check read it gets the whole check again: the
    refusal is the one a start without an earlier check gives."""
    checked = check_start(project, "myapp", component="test", compose_files=FILES)
    change(project.project_dir("myapp"))
    with docker_calls() as seen, pytest.raises(ComposeRefused, match=refusal):
        compose_up_checked(project, "myapp", component="test", compose_files=FILES,
                           earlier=checked)
    assert not seen.other_matching("compose", "up")


def test_an_install_opened_since_the_check_refuses_the_start(project) -> None:
    from boxmunge.release_txn import open_txn
    checked = check_start(project, "myapp", component="test", compose_files=FILES)
    open_txn(project, "myapp", source="bundle", ref="v2", replaced_ref=None,
             staged_id=None, snapshot="")
    with pytest.raises(ComposeRefused, match="install"):
        compose_up_checked(project, "myapp", component="test", compose_files=FILES,
                           earlier=checked)


def test_a_container_holding_a_refused_mount_refuses_the_start(project, monkeypatch) -> None:
    """The containers are inspected at the start too: restore runs one
    between its check and its last start."""
    checked = check_start(project, "myapp", component="test", compose_files=FILES)
    monkeypatch.setattr("boxmunge.docker_containers.container_bind_sources",
                        lambda name: [(str(project.project_dir("myapp")), True)])
    with pytest.raises(ComposeRefused, match="redeploy to replace it"):
        compose_up_checked(project, "myapp", component="test", compose_files=FILES,
                           earlier=checked)
    # ... unless the start replaces every container, as resume's does.
    seen = _start(project, checked, deploying=True, force_recreate=True)
    assert seen.compose_config == []


def test_an_earlier_check_stands_in_only_for_the_start_it_checked(project) -> None:
    checked = check_start(project, "myapp", component="test", compose_files=FILES)
    for kwargs, error in [
        ({"compose_files": ["compose.yml", "compose.boxmunge.yml"]}, "compose.boxmunge.yml"),
        ({"compose_files": FILES, "record": True}, "records"),
    ]:
        with pytest.raises(ValueError, match=error):
            compose_up_checked(project, "myapp", component="test", earlier=checked, **kwargs)
    with pytest.raises(ValueError, match="myapp"):
        compose_up_checked(project, "other", component="test", compose_files=FILES,
                           earlier=checked)
    with pytest.raises(TypeError, match="CheckedStart"):
        compose_up_checked(project, "myapp", component="test", compose_files=FILES,
                           earlier=True)
