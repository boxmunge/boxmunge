"""Integration: included files resolve where real `docker compose config`
resolves them (tests/test_compose_include_base.py has the unit cases).

Compose resolves an included file's relative paths against the include
entry's project_directory, or the directory of the entry's first path, not
the included file's own directory. Each escape below plants a decoy inside
the project where a file-relative reading would look, while Compose really
reads another project's file.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from boxmunge import compose_resolve
from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.paths import BoxPaths

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not on PATH"),
]

PROJDIR = {"include": [{"path": "./sub/deep/inc.yml", "project_directory": "./sub"}]}
MULTI = {"include": [{"path": ["./a/x.yml", "./b/deep/y.yml"]}]}

ESCAPES = {
    "project_directory env_file": (PROJDIR, "sub/deep/inc.yml", {"services": {"leak": {
        "image": "busybox", "env_file": "../../victim/secrets.env"}}}),
    "project_directory label_file": (PROJDIR, "sub/deep/inc.yml", {"services": {"leak": {
        "image": "busybox", "label_file": "../../victim/secrets.env"}}}),
    "project_directory extends": (PROJDIR, "sub/deep/inc.yml", {"services": {"leak": {
        "extends": {"file": "../../victim/ext.yml", "service": "base"}}}}),
    "multi-path env_file": (MULTI, "b/deep/y.yml", {"services": {"leak": {
        "image": "busybox", "env_file": "../../victim/secrets.env"}}}),
    "multi-path extends": (MULTI, "b/deep/y.yml", {"services": {"leak": {
        "extends": {"file": "../../victim/ext.yml", "service": "base"}}}}),
}


def _write(root: Path, files: dict[str, object]) -> None:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else yaml.safe_dump(content))


@pytest.fixture
def box(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    _write(paths.project_dir("victim"), {
        "secrets.env": "DB_PASSWORD=victim-secret\n",
        "ext.yml": {"services": {"base": {"image": "busybox", "labels": {"from": "outside"}}}},
    })
    return paths


def _evil(paths: BoxPaths, top: dict, inc: str, inc_doc: dict) -> Path:
    project_dir = paths.project_dir("evil")
    _write(project_dir, {
        "compose.yml": {**top, "services": {"web": {"image": "busybox"}}},
        inc: inc_doc,
        "a/x.yml": {"services": {"xa": {"image": "busybox"}}},
        "victim/secrets.env": "X=decoy\n",
        "victim/ext.yml": {"services": {"base": {"image": "busybox",
                                                 "labels": {"from": "inside"}}}},
    })
    return project_dir / "compose.yml"


@pytest.mark.parametrize("top,inc,inc_doc", ESCAPES.values(), ids=ESCAPES.keys())
def test_compose_really_reads_the_other_project(
    box: BoxPaths, top: dict, inc: str, inc_doc: dict,
) -> None:
    """The premise: real Compose resolves these against the entry's base."""
    model = compose_resolve.resolve_compose_config(_evil(box, top, inc, inc_doc), "evil")
    leak = model["services"]["leak"]
    victim = box.project_dir("victim")
    env = [e["path"] for e in leak.get("env_file", [])]
    labels = leak.get("labels", {})
    assert (env == [str(victim / "secrets.env")] or labels.get("from") == "outside"
            or labels.get("DB_PASSWORD") == "victim-secret"), leak


@pytest.mark.parametrize("top,inc,inc_doc", ESCAPES.values(), ids=ESCAPES.keys())
def test_escape_through_include_base_is_refused(
    box: BoxPaths, top: dict, inc: str, inc_doc: dict,
) -> None:
    compose = _evil(box, top, inc, inc_doc)
    with pytest.raises(ComposeSecurityError, match=r"victim.*outside the project.*prod-deploy evil"):
        validate_user_compose(compose, box, project_name="evil")


def test_model_check_refuses_what_a_diverging_walk_would_miss(
    box: BoxPaths, monkeypatch,
) -> None:
    """Belt and braces: with the literal walk blinded, the env_file real
    Compose resolves outside the project is still refused."""
    compose = _evil(box, *ESCAPES["project_directory env_file"])
    monkeypatch.setattr(compose_resolve, "walk_references", lambda *a, **kw: ([], []))
    with pytest.raises(ComposeSecurityError, match=r"env_file .*victim/secrets.env.*outside"):
        validate_user_compose(compose, box, project_name="evil")


def test_walk_and_compose_agree_on_the_files_an_include_reads(box: BoxPaths) -> None:
    """A benign project: every env file of the real model is a file the
    walk recorded, so the control record hashes what Compose reads."""
    project_dir = box.project_dir("good")
    _write(project_dir, {
        "compose.yml": {"include": [
            {"path": ["./a/x.yml", "./b/deep/y.yml"]},
            {"path": "./sub/deep/inc.yml", "project_directory": "./sub"},
        ], "services": {"web": {"image": "busybox"}}},
        "a/x.yml": {"services": {"xa": {"image": "busybox"}}},
        "b/deep/y.yml": {"services": {"yb": {"image": "busybox", "env_file": "y.env"}}},
        "a/y.env": "Y=1\n",
        "sub/deep/inc.yml": {"include": ["n/nest.yml"], "services": {
            "si": {"image": "busybox", "env_file": "s.env"}}},
        "sub/s.env": "S=1\n",
        "sub/n/nest.yml": {"services": {"nest": {"image": "busybox", "env_file": "n.env"}}},
        "sub/n/n.env": "N=1\n",
    })
    compose = project_dir / "compose.yml"
    validate_user_compose(compose, box, project_name="good")
    model = compose_resolve.resolve_compose_config(compose, "good")
    _, read_files = compose_resolve.walk_references(compose, (project_dir,))
    model_files = compose_resolve.model_env_files(model, project_dir)
    assert {project_dir / "a/y.env", project_dir / "sub/s.env",
            project_dir / "sub/n/n.env"} == set(model_files)
    assert set(model_files) <= set(read_files)
