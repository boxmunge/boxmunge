"""Integration: `include:` against real `docker compose config`
(tests/test_compose_include_base.py has the unit cases).

boxmunge allows an include entry only as a path or a list of paths naming
files inside the project, two levels deep; an included file's relative
paths resolve against its entry's first path's directory. Each escape
below makes real Compose read another project's file (the premise test
proves it), and validation refuses it.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from boxmunge import compose_references, compose_resolve, docker
from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.paths import BoxPaths

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not on PATH"),
]


def _top(include: list) -> dict:
    return {"include": include, "services": {"web": {"image": "busybox"}}}


def _svc(**kw) -> dict:
    return {"services": {"leak": {"image": "busybox", **kw}}}


_ENV = {"environment": {"S": "${DB_PASSWORD:-unset}"}}
_PROJDIR = [{"path": "./sub/deep/inc.yml", "project_directory": "./sub"}]
_MULTI = [{"path": ["./a/x.yml", "./b/deep/y.yml"]}]

# (files of the evil project, what the model shows when Compose read the
# victim project, what the refusal says). `victim/` inside the evil project
# is the decoy a file-relative reading would find.
ESCAPES = {
    "project_directory env_file": ({
        "compose.yml": _top(_PROJDIR),
        "sub/deep/inc.yml": _svc(env_file="../../victim/secrets.env"),
        "sub/deep/victim/secrets.env": "X=decoy\n",
    }, "victim/secrets.env", "sets project_directory"),
    "project_directory label_file": ({
        "compose.yml": _top(_PROJDIR),
        "sub/deep/inc.yml": _svc(label_file="../../victim/secrets.env"),
        "sub/deep/victim/secrets.env": "X=decoy\n",
    }, "victim-secret", "sets project_directory"),
    "project_directory extends": ({
        "compose.yml": _top(_PROJDIR),
        "sub/deep/inc.yml": {"services": {"leak": {
            "extends": {"file": "../../victim/ext.yml", "service": "base"}}}},
        "sub/deep/victim/ext.yml": {"services": {"base": {"image": "busybox"}}},
    }, '"from": "victim"', "sets project_directory"),
    "path list env_file": ({
        "compose.yml": _top(_MULTI),
        "a/x.yml": {"services": {"xa": {"image": "busybox"}}},
        "b/deep/y.yml": _svc(env_file="../../victim/secrets.env"),
        "b/victim/secrets.env": "X=decoy\n",
    }, "victim/secrets.env", "victim.*outside the project"),
    "path list extends": ({
        "compose.yml": _top(_MULTI),
        "a/x.yml": {"services": {"xa": {"image": "busybox"}}},
        "b/deep/y.yml": {"services": {"leak": {
            "extends": {"file": "../../victim/ext.yml", "service": "base"}}}},
        "b/victim/ext.yml": {"services": {"base": {"image": "busybox"}}},
    }, '"from": "victim"', "victim.*outside the project"),
    # The second review's residual cases.
    "missing project_directory moves the base up": ({
        "compose.yml": _top([{"path": "sub/inc.yml", "project_directory": "nonexist"}]),
        "sub/inc.yml": _svc(label_file="../victim/secrets.env"),
        "victim/secrets.env": "X=decoy\n",
    }, "victim-secret", "sets project_directory"),
    "include env_file three levels deep": ({
        "compose.yml": _top(["p/inc.yml"]),
        "p/inc.yml": {"include": ["q/inc2.yml"]},
        "p/q/inc2.yml": {"include": [{"path": "i3.yml", "env_file": "../../victim/secrets.env"}]},
        "p/q/i3.yml": _svc(**_ENV),
        "p/victim/secrets.env": "DB_PASSWORD=decoy\n",
    }, "victim-secret", "sets env_file"),
    "project_directory chain to another project's .env": ({
        "compose.yml": _top([{"path": "p/deep/inc.yml", "project_directory": "p"}]),
        "p/deep/inc.yml": {"include": [{"path": "q/deep2/inc2.yml", "project_directory": "q"}]},
        "p/q/deep2/inc2.yml": {"include": [{"path": "../../victim/i3.yml",
                                            "project_directory": "../../victim"}]},
        "victim/i3.yml": _svc(**_ENV),
        "victim/.env": "DB_PASSWORD=decoy\n",
    }, "victim-dotenv", "sets project_directory"),
    "project_directory chain shifting a depth-4 path": ({
        "compose.yml": _top([{"path": "p/deep/inc.yml", "project_directory": "p"}]),
        "p/deep/inc.yml": {"include": [{"path": "q/deep2/inc2.yml", "project_directory": "q"}]},
        "p/q/deep2/inc2.yml": {"include": [{"path": "r/i3.yml", "project_directory": "r"}]},
        "p/q/r/i3.yml": {"include": ["../../../victim/inc.yml"]},
        "victim/inc.yml": {"services": {"foreign": {"image": "busybox",
                                                    "labels": {"from": "decoy"}}}},
    }, '"from": "victim"', "sets project_directory"),
}


def _write(root: Path, files: dict[str, object]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else yaml.safe_dump(content))
    return root / "compose.yml"


@pytest.fixture
def box(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    _write(paths.project_dir("victim"), {
        "compose.yml": "services: {}\n",
        "secrets.env": "DB_PASSWORD=victim-secret\n",
        ".env": "DB_PASSWORD=victim-dotenv\n",
        "ext.yml": {"services": {"base": {"image": "busybox", "labels": {"from": "victim"}}}},
        "inc.yml": {"services": {"foreign": {"image": "busybox", "labels": {"from": "victim"}}}},
    })
    return paths


@pytest.mark.parametrize("files,leaked,_match", ESCAPES.values(), ids=ESCAPES.keys())
def test_compose_really_reads_the_other_project(
    box: BoxPaths, files: dict, leaked: str, _match: str,
) -> None:
    """The premise: real Compose reads the victim project for every shape.
    Compose itself is asked, with the call the resolve makes: the resolve
    raises what boxmunge's own walk of the files refuses, as these are."""
    compose = _write(box.project_dir("evil"), files)
    model = json.loads(docker.compose_config(
        compose.parent, [compose.name], project_name="evil", all_profiles=True))
    assert leaked in json.dumps(model), model


@pytest.mark.parametrize("files,_leaked,match", ESCAPES.values(), ids=ESCAPES.keys())
def test_escape_is_refused(box: BoxPaths, files: dict, _leaked: str, match: str) -> None:
    compose = _write(box.project_dir("evil"), files)
    with pytest.raises(ComposeSecurityError, match=rf"{match}.*prod-deploy evil\.$"):
        validate_user_compose(compose, box, project_name="evil")


def test_scp_style_git_remote_is_refused(box: BoxPaths) -> None:
    """Compose would fetch `user@host:repo` with git, for include and extends."""
    compose = _write(box.project_dir("evil"), {"compose.yml": {
        "include": ["bob@192.0.2.1:repo.git"],
        "services": {"web": {"extends": {"file": "bob@192.0.2.1:repo.git", "service": "a"}}}}})
    problems, _ = compose_references.walk_references(compose, (compose.parent,))
    assert len(problems) == 2 and all("is remote" in p for p in problems)
    with pytest.raises(ComposeSecurityError, match="is remote"):
        validate_user_compose(compose, box, project_name="evil")


def test_model_check_refuses_what_a_diverging_walk_would_miss(
    box: BoxPaths, monkeypatch,
) -> None:
    """Belt and braces: with the literal walk blinded, the env_file real
    Compose resolves outside the project is still refused."""
    compose = _write(box.project_dir("evil"), ESCAPES["path list env_file"][0])
    walk = compose_references.walk_sources
    monkeypatch.setattr(compose_references, "walk_sources",
                        lambda *a, **kw: ([], [], walk(*a, **kw)[2]))
    with pytest.raises(ComposeSecurityError, match=r"env_file .*victim/secrets.env.*outside"):
        validate_user_compose(compose, box, project_name="evil")


def test_walk_and_compose_agree_on_the_files_the_subset_reads(box: BoxPaths) -> None:
    """A benign project using the whole subset, two levels deep: every env
    file of the real model is a file the walk recorded, and the services the
    walk's census expects are the ones Compose resolved."""
    project_dir = box.project_dir("good")
    compose = _write(project_dir, {
        "compose.yml": _top([{"path": ["./a/x.yml", "./b/deep/y.yml"]}, "./c/inc.yml"]),
        "a/x.yml": {"services": {"xa": {"image": "busybox"}}},
        "b/deep/y.yml": {"include": ["n/nest.yml"], "services": {
            "yb": {"image": "busybox", "env_file": "y.env"}}},
        "a/y.env": "Y=1\n",
        "a/n/nest.yml": {"services": {"nest": {"image": "busybox", "env_file": "n.env",
                                               "extends": {"file": "e/ext.yml",
                                                           "service": "base"}}}},
        "b/deep/n/nest.yml": {"services": {"decoy": {"image": "busybox"}}},
        "a/n/n.env": "N=1\n",
        "a/n/e/ext.yml": {"services": {"base": {"image": "busybox", "env_file": "e.env"}}},
        "a/n/e/e.env": "E=1\n",
        "c/inc.yml": {"services": {"ci": {"image": "busybox", "env_file": "c.env"}}},
        "c/c.env": "C=1\n",
    })
    validate_user_compose(compose, box, project_name="good")
    model = compose_resolve.resolve_compose_config(compose, "good")
    assert set(model["services"]) == {"web", "xa", "yb", "nest", "ci"}
    problems, read_files = compose_references.walk_references(compose, (project_dir,))
    model_files = set(compose_resolve.model_env_files(model, project_dir))
    assert problems == []
    assert model_files == {project_dir / f for f in (
        "a/y.env", "a/n/n.env", "a/n/e/e.env", "c/c.env")}
    assert model_files <= set(read_files)
