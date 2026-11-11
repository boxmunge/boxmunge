# SPDX-License-Identifier: Apache-2.0
"""A start runs on what its check resolved, and only a check can say so."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

import boxmunge
from boxmunge import checked_start
from boxmunge.checked_start import CheckedStart
from boxmunge.compose_guard import check_start
from tests.deploy_helpers import mark_deployed

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
