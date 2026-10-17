"""Tests for boxmunge add-git-project command."""
import json
import os
import pwd
import subprocess
import pytest
from pathlib import Path
from unittest.mock import patch

from boxmunge import as_deploy, fs_nofollow, git_slot
from boxmunge.commands.add_git_project_cmd import (
    cmd_add_git_project, run_add_git_project,
)
from boxmunge.log import _reset_logger
from boxmunge.paths import BoxPaths
from boxmunge.state import read_state
from tests.git_helpers import origin_with

VALID_MANIFEST = """\
id: 01TESTULID0000000000000000
project: testapp
source: git
repo: git@github.com:org/testapp.git
ref: main
hosts:
  - testapp.example.com
services:
  web:
    port: 8080
    routes:
      - path: /
"""


@pytest.fixture
def origin(tmp_path: Path) -> str:
    """A local repository to clone: no network."""
    repo, _work = origin_with(tmp_path, {
        "manifest.yml": VALID_MANIFEST,
        "compose.yml": "services:\n  web:\n    image: nginx\n",
    })
    return str(repo)


class TestRunAddGitProject:
    def test_creates_project_dir(self, paths: BoxPaths, origin: str) -> None:
        assert run_add_git_project("testapp", origin, paths, ref="main") == 0
        project_dir = paths.project_dir("testapp")
        assert (project_dir / "repo" / ".git").is_dir()
        assert (project_dir / "manifest.yml").resolve() == \
            (project_dir / "repo" / "manifest.yml").resolve()

    def test_records_deploy_state(self, paths: BoxPaths, origin: str) -> None:
        run_add_git_project("testapp", origin, paths, ref="main")
        state = read_state(paths.project_deploy_state("testapp"))
        assert state.get("project_id") == "01TESTULID0000000000000000"

    def test_rejects_existing_project(self, paths: BoxPaths) -> None:
        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True)
        (pdir / "manifest.yml").write_text("project: testapp\n")

        result = run_add_git_project(
            "testapp", "git@github.com:org/testapp.git", paths
        )
        assert result == 1

    def test_a_failed_clone_is_an_error(self, paths: BoxPaths, tmp_path: Path,
                                        capsys) -> None:
        assert run_add_git_project("testapp", str(tmp_path / "nowhere"), paths) == 1
        assert "git clone of" in capsys.readouterr().err

    def test_a_url_is_never_read_as_an_option(self, paths: BoxPaths, tmp_path: Path) -> None:
        marker = tmp_path / "ran"
        url = f"--upload-pack=touch {marker}"
        assert run_add_git_project("testapp", url, paths) == 1
        assert not marker.exists()


class TestAddGitProjectAsRoot:
    """An operator's `sudo boxmunge-server add-git-project`: git clones as
    deploy, and the project tree it leaves is deploy's."""

    @pytest.fixture
    def as_root(self, monkeypatch):
        me = os.getuid()
        for module in (as_deploy, git_slot, fs_nofollow):
            monkeypatch.setattr(module, "running_as_root", lambda: True)
        monkeypatch.setattr(pwd, "getpwnam", lambda name: pwd.struct_passwd(
            (name, "x", me, 5678, "", "/home/deploy", "/bin/sh")))
        monkeypatch.setattr(fs_nofollow, "_deploy_owner", lambda: (me, os.getgid()))
        spawned, chowned = [], []
        real_popen, real_chown = subprocess.Popen, os.chown

        def popen(argv, **kw):
            spawned.append((argv, kw))
            return real_popen(argv, **{k: v for k, v in kw.items()
                                       if k not in ("user", "group", "extra_groups")})

        def chown(path, *args, **kw):
            chowned.append(os.fspath(path))
            return real_chown(path, *args, **kw)
        monkeypatch.setattr(as_deploy.subprocess, "Popen", popen)
        monkeypatch.setattr(fs_nofollow.os, "chown", chown)
        return spawned, chowned

    def test_the_clone_runs_as_deploy(self, paths: BoxPaths, origin: str, as_root) -> None:
        spawned, _ = as_root
        assert run_add_git_project("testapp", origin, paths, ref="main") == 0
        (argv, kw), = [s for s in spawned if "clone" in s[0]]
        assert (kw["user"], kw["group"], kw["extra_groups"]) == (os.getuid(), 5678, [])
        assert kw["stdin"] is subprocess.DEVNULL and kw["start_new_session"] is True
        assert kw["env"]["HOME"] == "/home/deploy"
        assert argv[1:3] == ["-c", "core.hooksPath=/dev/null"]
        assert argv[argv.index("--") + 1] == origin

    def test_the_project_tree_is_handed_to_deploy(self, paths: BoxPaths, origin: str,
                                                  as_root) -> None:
        _, chowned = as_root
        assert run_add_git_project("testapp", origin, paths, ref="main") == 0
        project_dir = paths.project_dir("testapp")
        for name in ("backups", "data", "compose.yml", "manifest.yml"):
            assert str(project_dir / name) in chowned, (name, chowned)
        assert str(project_dir) in chowned  # made for the clone, deploy's before it runs

    def test_an_existing_project_dir_deploy_does_not_own_is_refused(
            self, paths: BoxPaths, origin: str, monkeypatch, as_root, capsys) -> None:
        paths.project_dir("testapp").mkdir(parents=True)
        other = os.getuid() + 1
        monkeypatch.setattr(pwd, "getpwnam", lambda name: pwd.struct_passwd(
            (name, "x", other, 5678, "", "/home/deploy", "/bin/sh")))
        assert run_add_git_project("testapp", origin, paths) == 1
        assert "must be owned by the deploy user" in capsys.readouterr().err


class TestAddGitProjectLogging:
    def setup_method(self):
        _reset_logger()

    def teardown_method(self):
        _reset_logger()

    def test_uses_add_git_project_component(self, paths: BoxPaths, origin: str) -> None:
        """Component must match the CLI verb 'add-git-project' (not 'add-project')."""
        run_add_git_project("testapp", origin, paths, ref="main")
        entries = [
            json.loads(line)
            for line in paths.log_file.read_text().strip().splitlines()
            if line
        ]
        components = {e.get("component") for e in entries}
        assert "add-git-project" in components
        assert "add-project" not in components


class TestErrorOutputGoesToStderr:
    """Audit H-4: ERROR prints in commands/*.py must go to stderr.

    Single integration check covering the sweep — exhaustive per-line
    coverage would be mechanical noise. add-git-project with no args is
    a representative example and exercises ``cmd_add_git_project``.
    """

    def test_missing_args_writes_to_stderr(self, capfd) -> None:
        # Empty args path exits before touching any boxmunge state, so no
        # monkeypatch fixture is needed — only the usage error itself.
        with pytest.raises(SystemExit) as exc:
            cmd_add_git_project([])
        assert exc.value.code == 2
        captured = capfd.readouterr()
        # Usage prints to stderr
        assert "Usage" in captured.err
        assert captured.out == ""


class TestOverlappingName:
    def test_name_extending_a_registered_project_refused_before_clone(
        self, paths: BoxPaths, capsys,
    ) -> None:
        from boxmunge.project_registry import add_project
        add_project("testapp", paths)
        with patch("boxmunge.commands.add_git_project_cmd.clone") as clone:
            assert run_add_git_project("testapp-admin", "git@example.com:o/r.git", paths) == 1
        assert "container names" in capsys.readouterr().err
        clone.assert_not_called()
