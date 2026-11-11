# SPDX-License-Identifier: Apache-2.0
"""A start runs on what its check resolved, and only a check can say so."""
from __future__ import annotations

import dataclasses
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
    fields = {f.name: getattr(checked, f.name) for f in dataclasses.fields(checked)}
    with pytest.raises(TypeError, match="compose_guard.check_start"):
        CheckedStart(**fields, by=object())
    # ... nor a changed copy of one: the token is not the copy's to pass on.
    with pytest.raises((TypeError, ValueError), match="'by'"):
        dataclasses.replace(checked, model={})
    assert not hasattr(checked, "by")


def test_only_compose_guard_issues_one() -> None:
    """`issue` is the one way past the constructor: no module of boxmunge
    but compose_guard may call it, and none may construct a CheckedStart,
    reach for the token `issue` holds, or set a member of one."""
    src = Path(boxmunge.__file__).parent
    building = re.compile(r"\bCheckedStart\(|_BY_A_CHECK|checked_start\.issue\(|__setattr__")
    issuing = re.compile(r"\bissue\(|import [^\n]*\bissue\b")
    found = {}
    for path in sorted(src.rglob("*.py")):
        text = path.read_text()
        if path.name == "checked_start.py":
            continue
        hits = set(building.findall(text))
        if "checked_start" in text:
            hits |= set(issuing.findall(text))
        if hits:
            found[str(path.relative_to(src))] = sorted(hits)
    assert found == {"compose_guard.py": ["checked_start.issue(", "issue("]}
    assert len(re.findall(r"checked_start\.issue\(", (src / "compose_guard.py").read_text())) == 2
    # In its own module `issue` alone constructs one, and nothing copies one.
    own = (src / "checked_start.py").read_text()
    assert len(re.findall(r"\bCheckedStart\(", own)) == 1
    assert not re.search(r"\breplace\(|__setattr__|import copy", own)
    assert checked_start.issue.__doc__


def test_what_a_check_read_cannot_be_rewritten(project) -> None:
    checked = check_start(project, "myapp", component="test", compose_files=FILES)
    with pytest.raises(TypeError):
        checked.control["compose.yml"] = "0" * 64
    with pytest.raises(TypeError):
        checked.kinds["data"] = "file"
    with pytest.raises(TypeError):
        checked.places[str(project.project_dir("myapp") / "compose.yml")] = "/etc/passwd"


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


# -- what the earlier check stands on is what the full check refuses ----------

def _redeployed(paths, files: dict[str, str]):
    project_dir = paths.project_dir("myapp")
    for name, content in files.items():
        (project_dir / name).parent.mkdir(parents=True, exist_ok=True)
        (project_dir / name).write_text(content)
    mark_deployed(paths, "myapp")
    return project_dir


def _refusal(paths, **kwargs) -> str:
    with docker_calls() as seen, pytest.raises(ComposeRefused) as refused:
        compose_up_checked(paths, "myapp", component="test", compose_files=FILES, **kwargs)
    assert not seen.other_matching("compose", "up")
    return str(refused.value)


def _linked_out(project_dir: Path, name: str, outside: Path) -> None:
    """Move `name` (a file or a directory) out of the project and leave a
    link to it: the same bytes, read from somewhere else."""
    (project_dir / name).rename(outside)
    (project_dir / name).symlink_to(outside)


@pytest.mark.parametrize("files, moved, refusal", [
    ({"compose.yml": "services:\n  web:\n    image: nginx\n    env_file: secrets.env\n",
      "secrets.env": "A=1\n"}, "secrets.env", "env_file 'secrets.env' resolves to"),
    ({"compose.yml": "services:\n  web:\n    image: nginx\n    env_file: conf/app.env\n",
      "conf/app.env": "A=1\n"}, "conf", "env_file 'conf/app.env' resolves to"),
    ({"compose.yml": "include: [sub/inc.yml]\nservices:\n  web:\n    image: nginx\n",
      "sub/inc.yml": "services:\n  db:\n    image: postgres\n"}, "sub",
     "include 'sub/inc.yml' resolves to"),
])
def test_a_read_file_linked_out_of_the_project_since_the_check_is_refused(
        project, tmp_path, files, moved, refusal) -> None:
    """secrets.env is not hashed (`secrets set` rewrites it), and a hash
    opens a file through whatever its parent directories have become: the
    same bytes behind a link out of the project are not the file the check
    read. The start is refused in the full check's own words."""
    project_dir = _redeployed(project, files)
    checked = check_start(project, "myapp", component="test", compose_files=FILES)
    _linked_out(project_dir, moved, tmp_path / "elsewhere")
    in_full = _refusal(project)
    assert refusal in in_full and "outside the project directory" in in_full
    assert _refusal(project, earlier=checked) == in_full


def test_a_read_file_linked_elsewhere_in_the_project_is_checked_in_full(project) -> None:
    """A link that stays inside the project is the full check's to judge."""
    project_dir = _redeployed(project, {
        "compose.yml": "services:\n  web:\n    image: nginx\n    env_file: conf/app.env\n",
        "conf/app.env": "A=1\n"})
    checked = check_start(project, "myapp", component="test", compose_files=FILES)
    (project_dir / "conf").rename(project_dir / "kept")
    (project_dir / "conf").symlink_to("kept")
    assert _start(project, checked).compose_config


OVERLAID = ["compose.yml", "compose.boxmunge.yml"]


def _overlaid_check(paths):
    _redeployed(paths, {"compose.boxmunge.yml": "services:\n  web: {}\n"})
    return check_start(paths, "myapp", component="test", compose_files=OVERLAID)


def test_an_overlay_gone_stale_since_the_check_refuses_the_start(project, monkeypatch) -> None:
    checked = _overlaid_check(project)
    monkeypatch.setattr("boxmunge.compose_guard.stale_overlay_problem",
                        lambda paths, name: "the users record changed")
    with docker_calls() as seen, pytest.raises(ComposeRefused, match="users record changed"):
        compose_up_checked(project, "myapp", component="test", compose_files=OVERLAID,
                           earlier=checked)
    assert not seen.other_matching("compose", "up")


def test_the_files_are_hashed_last_on_an_earlier_check(project, monkeypatch) -> None:
    """As in the full check: the containers are asked about first, so the
    comparison with what the check read is the last thing before `up`."""
    from boxmunge import bind_sources, docker_containers
    checked = check_start(project, "myapp", component="test", compose_files=FILES)
    order = []
    hashes, held = bind_sources.control_hashes, docker_containers.container_bind_sources
    monkeypatch.setattr(bind_sources, "control_hashes",
                        lambda *a, **kw: (order.append("hashes"), hashes(*a, **kw))[1])
    monkeypatch.setattr(docker_containers, "container_bind_sources",
                        lambda name: (order.append("containers"), held(name))[1])
    _start(project, checked)
    assert order == ["containers", "hashes"]
