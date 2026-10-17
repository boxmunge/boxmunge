# SPDX-License-Identifier: Apache-2.0
"""deploy.pre_deploy is project code: it runs as deploy, even when root deploys.

An operator's `sudo boxmunge-server prod-deploy` (or rollback, or promote)
makes boxmunge root, and the hook must not inherit that. Root's spawn
drops to deploy's uid, gid and groups, in deploy's shell environment, with
no stdin and no controlling terminal. tests/integration/test_hook_as_deploy.py
proves it with a real root and a real deploy user.
"""
import os
import pwd
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.commands.deploy import run_pre_deploy_hook
from boxmunge.paths import BoxPaths

DEPLOY = pwd.struct_passwd(("deploy", "x", 1500, 1500, "", "/home/deploy",
                            "/opt/boxmunge/bin/boxmunge-shell"))
ROOT_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "USER": "root",
            "SUDO_USER": "supervisor", "LD_PRELOAD": "/tmp/x.so", "PYTHONPATH": "/tmp",
            "BASH_ENV": "/tmp/x", "LANG": "C.UTF-8", "TERM": "xterm"}
MANIFEST = {"deploy": {"pre_deploy": "boxmunge-scripts/pre-deploy.sh --flag"}}


@pytest.fixture
def paths(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    paths.project_dir("demo").mkdir(parents=True)
    return paths


def _spawn_as_root(paths: BoxPaths, getpwnam=lambda name: DEPLOY):
    with patch.dict(os.environ, ROOT_ENV, clear=True), \
            patch("boxmunge.as_deploy.running_as_root", return_value=True), \
            patch("boxmunge.as_deploy.pwd.getpwnam", side_effect=getpwnam), \
            patch("boxmunge.as_deploy.os.getgrouplist", return_value=[1500, 998]), \
            patch("boxmunge.commands.deploy.subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        rc = run_pre_deploy_hook("demo", paths, MANIFEST)
    return rc, run


def test_root_runs_the_hook_as_deploy(paths: BoxPaths) -> None:
    rc, run = _spawn_as_root(paths)
    assert rc == 0
    argv, kwargs = run.call_args.args[0], run.call_args.kwargs
    assert argv == ["boxmunge-scripts/pre-deploy.sh", "--flag"]
    assert (kwargs["user"], kwargs["group"], kwargs["extra_groups"]) == (1500, 1500, [1500, 998])
    assert kwargs["cwd"] == paths.project_dir("demo")
    assert kwargs["shell"] is False
    # No terminal or stdin to inject into root's session, no fd but std.
    assert kwargs["stdin"] is subprocess.DEVNULL and kwargs["start_new_session"] is True
    assert kwargs.get("close_fds", True) is True and not kwargs.get("pass_fds")


def test_root_gives_the_hook_deploys_shell_environment(paths: BoxPaths) -> None:
    from boxmunge.as_deploy import SHELL_PATH
    _, run = _spawn_as_root(paths)
    assert run.call_args.kwargs["env"] == {
        "LANG": "C.UTF-8", "TERM": "xterm", "PATH": SHELL_PATH, "HOME": "/home/deploy",
        "USER": "deploy", "LOGNAME": "deploy", "SHELL": "/opt/boxmunge/bin/boxmunge-shell"}


def test_root_without_a_deploy_user_refuses_to_run_the_hook(paths: BoxPaths, capsys) -> None:
    def missing(name):
        raise KeyError(name)
    rc, run = _spawn_as_root(paths, getpwnam=missing)
    assert rc == 1
    run.assert_not_called()
    err = capsys.readouterr().err
    assert "deploy user" in err and "not run" in err


def test_deploy_runs_the_hook_as_itself_in_its_shell_environment(paths: BoxPaths) -> None:
    project_dir = paths.project_dir("demo")
    (project_dir / "boxmunge-scripts").mkdir()
    script = project_dir / "boxmunge-scripts" / "pre-deploy.sh"
    script.write_text("#!/bin/sh\nid -u > uid\nenv > env\n")
    script.chmod(0o755)
    with patch.dict(os.environ, {**ROOT_ENV, "HOME": "/elsewhere"}, clear=True):
        assert run_pre_deploy_hook("demo", paths, MANIFEST) == 0
    assert (project_dir / "uid").read_text().strip() == str(os.getuid())
    seen = dict(line.split("=", 1) for line in (project_dir / "env").read_text().splitlines()
                if "=" in line)
    assert seen["HOME"] == pwd.getpwuid(os.getuid()).pw_dir
    for name in ("LD_PRELOAD", "PYTHONPATH", "BASH_ENV", "SUDO_USER"):
        assert name not in seen
