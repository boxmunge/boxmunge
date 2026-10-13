# SPDX-License-Identifier: Apache-2.0
"""Bundle content policy: build real tarballs and assert their member lists."""

import os
import tarfile
from pathlib import Path

import pytest

from boxmunge_cli.bundle_cmd import run_bundle

_MANIFEST = """\
id: 01TESTULID0000000000000000
project: myapp
source: bundle
hosts:
  - myapp.example.com
services:
  web:
    port: 8080
    routes: [{path: /}]
"""


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "work" / "myapp"
    project.mkdir(parents=True)
    (project / "manifest.yml").write_text(_MANIFEST)
    (project / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    return project


def _touch(root: Path, rel: str, text: str = "x") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _bundle(project: Path, out: Path, *extra: str) -> tuple[int, list[str]]:
    out.mkdir(exist_ok=True)
    rc = run_bundle(str(project), output=str(out))
    tarballs = sorted(out.glob("myapp-*.tar.gz"))
    if rc != 0:
        assert not tarballs, "a refused bundle must not leave a tarball behind"
        return rc, []
    with tarfile.open(tarballs[-1]) as tar:
        return rc, sorted(tar.getnames())


def test_junk_never_ships(tmp_path: Path) -> None:
    project = _project(tmp_path)
    for rel in [
        ".git/config", ".hg/store", ".svn/entries",
        ".env", ".env.production", ".boxmunge",
        ".venv/bin/python", "venv/lib/x.py", "node_modules/x/i.js",
        "__pycache__/a.pyc", "src/__pycache__/b.pyc", "src/c.pyc", ".DS_Store",
        "data/db.sqlite", "backups/old.age",
        "myapp-2026-01-01T000000.tar.gz",
    ]:
        _touch(project, rel)
    for rel in [".env.example", "project.env", "app.py", "src/main.py",
                "boxmunge-scripts/smoke.sh", "assets/data/seed.json"]:
        _touch(project, rel)

    rc, names = _bundle(project, tmp_path / "out")

    assert rc == 0
    assert names == sorted([
        "myapp", "myapp/.env.example", "myapp/app.py", "myapp/assets",
        "myapp/assets/data", "myapp/assets/data/seed.json", "myapp/boxmunge-scripts",
        "myapp/boxmunge-scripts/smoke.sh", "myapp/compose.yml", "myapp/manifest.yml",
        "myapp/project.env", "myapp/src", "myapp/src/main.py",
    ])


def test_members_carry_no_local_identity(tmp_path: Path) -> None:
    project = _project(tmp_path)
    out = tmp_path / "out"
    assert _bundle(project, out)[0] == 0
    with tarfile.open(next(out.glob("*.tar.gz"))) as tar:
        for m in tar.getmembers():
            assert (m.uid, m.gid, m.uname, m.gname) == (0, 0, "", "")


@pytest.mark.parametrize("rel", ["secrets.env", "config/secrets.env"])
def test_secrets_env_is_refused(tmp_path: Path, rel: str, capsys) -> None:
    project = _project(tmp_path)
    _touch(project, rel, "API_KEY=hunter2\n")
    assert _bundle(project, tmp_path / "out")[0] == 1
    assert "secrets set" in capsys.readouterr().err


def test_top_level_repo_dir_is_refused(tmp_path: Path, capsys) -> None:
    project = _project(tmp_path)
    _touch(project, "repo/README")
    assert _bundle(project, tmp_path / "out")[0] == 1
    assert "git mode" in capsys.readouterr().err


def test_nested_repo_dir_ships(tmp_path: Path) -> None:
    project = _project(tmp_path)
    _touch(project, "src/repo/x.py")
    rc, names = _bundle(project, tmp_path / "out")
    assert rc == 0 and "myapp/src/repo/x.py" in names


def test_refused_path_can_be_ignored_explicitly(tmp_path: Path) -> None:
    project = _project(tmp_path)
    _touch(project, "secrets.env", "API_KEY=hunter2\n")
    _touch(project, "repo/README")
    _touch(project, ".boxmungeignore", "secrets.env\n/repo/\n")
    rc, names = _bundle(project, tmp_path / "out")
    assert rc == 0
    assert not any("secrets.env" in n or n.startswith("myapp/repo") for n in names)
    assert "myapp/.boxmungeignore" not in names


def test_absolute_symlink_is_refused(tmp_path: Path, capsys) -> None:
    project = _project(tmp_path)
    os.symlink("/etc/passwd", project / "passwd-link")
    assert _bundle(project, tmp_path / "out")[0] == 1
    assert "absolute symlink" in capsys.readouterr().err


def test_escaping_symlink_is_refused(tmp_path: Path, capsys) -> None:
    project = _project(tmp_path)
    os.symlink("../../", project / "outside-dir")
    assert _bundle(project, tmp_path / "out")[0] == 1
    assert "leaves the project tree" in capsys.readouterr().err


def test_in_tree_relative_symlink_ships_as_a_link(tmp_path: Path) -> None:
    project = _project(tmp_path)
    _touch(project, "static/index.html")
    os.symlink("static/index.html", project / "index.html")
    out = tmp_path / "out"
    assert _bundle(project, out)[0] == 0
    with tarfile.open(next(out.glob("*.tar.gz"))) as tar:
        link = tar.getmember("myapp/index.html")
        assert link.issym() and link.linkname == "static/index.html"


def test_fifo_is_refused(tmp_path: Path, capsys) -> None:
    project = _project(tmp_path)
    os.mkfifo(project / "pipe")
    assert _bundle(project, tmp_path / "out")[0] == 1
    assert "special file" in capsys.readouterr().err


def test_boxmungeignore_patterns(tmp_path: Path) -> None:
    project = _project(tmp_path)
    for rel in ["a.log", "logs/b.log", "keep.log", "build/out.js", "src/build/x.js",
                "docs/x/y/z.tmp", "docs/top.tmp", "docs/top.txt", "data/seed.json"]:
        _touch(project, rel)
    _touch(project, ".boxmungeignore",
           "# comment\n*.log\n!keep.log\n/build/\ndocs/**/*.tmp\n!data/\n")
    rc, names = _bundle(project, tmp_path / "out")
    assert rc == 0
    shipped = {n.removeprefix("myapp/") for n in names}
    assert {"keep.log", "src/build/x.js", "data/seed.json", "docs/top.txt"} <= shipped
    # As in git, "a/**/b" also matches "a/b".
    assert not {"a.log", "logs/b.log", "build/out.js", "docs/x/y/z.tmp", "docs/top.tmp"} & shipped


def test_ignore_cannot_reinclude_never_shipped(tmp_path: Path) -> None:
    project = _project(tmp_path)
    _touch(project, ".env", "SECRET=1\n")
    _touch(project, ".git/config")
    _touch(project, ".boxmungeignore", "!.env\n!.git/\n")
    rc, names = _bundle(project, tmp_path / "out")
    assert rc == 0
    assert "myapp/.env" not in names and "myapp/.git" not in names


def test_output_inside_project_never_nests_bundles(tmp_path: Path) -> None:
    project = _project(tmp_path)
    assert run_bundle(str(project), output=str(project)) == 0
    assert run_bundle(str(project), output=str(project)) == 0
    for tarball in project.glob("myapp-*.tar.gz"):
        with tarfile.open(tarball) as tar:
            assert not [n for n in tar.getnames() if n.endswith(".tar.gz")]


def test_missing_output_dir_is_an_error_not_a_traceback(tmp_path: Path, capsys) -> None:
    project = _project(tmp_path)
    rc = run_bundle(str(project), output=str(tmp_path / "missing" / "dir"))
    assert rc == 1
    assert "ERROR:" in capsys.readouterr().err


def test_excluded_paths_are_reported(tmp_path: Path, capsys) -> None:
    project = _project(tmp_path)
    _touch(project, "node_modules/x/i.js")
    _touch(project, ".env")
    assert _bundle(project, tmp_path / "out")[0] == 0
    err = capsys.readouterr().err
    assert "node_modules/" in err and ".env" in err


def test_list_prints_the_plan_and_writes_nothing(tmp_path: Path, capsys) -> None:
    project = _project(tmp_path)
    _touch(project, "app.py")
    _touch(project, ".env")
    out = tmp_path / "out"
    out.mkdir()
    assert run_bundle(str(project), output=str(out), list_only=True) == 0
    assert not list(out.iterdir())
    captured = capsys.readouterr()
    assert "app.py" in captured.out
    assert ".env" in captured.err
