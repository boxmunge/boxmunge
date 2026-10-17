# SPDX-License-Identifier: Apache-2.0
"""Running a command the way the deploy shell runs it.

The deploy shell hands its commands only the variables below. Code that
runs on the host from a project is deploy's (TRUST_MODEL.md): the
manifest's pre_deploy hook, and git in the project's repository, whose
config can run filters. It gets the same environment, and when boxmunge
runs as root (an operator's sudo) it drops to deploy rather than run as root.
"""
from __future__ import annotations

import os
import pwd
import signal
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from boxmunge.fs_nofollow import running_as_root

# Variables the shell passes on to the commands it runs. Anything else an SSH
# client got through (BASH_ENV, ENV, PYTHONPATH...) could run code in one of
# those commands before it does its job, so it is dropped here. This cannot
# undo what already acted when /bin/sh and python started this shell: the
# dynamic loader's LD_PRELOAD, LD_LIBRARY_PATH or GCONV_PATH. Against those
# the boundary is sshd, which accepts only LANG, LC_*, COLORTERM and NO_COLOR
# from deploy (src/boxmunge/sshd/00-boxmunge.conf, checked by install.sh and
# `health`). The proxy and TZ variables are machine-wide settings (pam_env)
# that deploy's outbound calls (image pulls, version checks) rely on.
KEPT_ENV = frozenset({"TERM", "LANG", "COLORTERM", "NO_COLOR",
                      "SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "SSH_ORIGINAL_COMMAND",
                      "http_proxy", "https_proxy", "no_proxy",
                      "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "TZ"})
SHELL_PATH = "/usr/local/bin:/usr/bin:/bin"


class NoDeployUser(RuntimeError):
    """Root was asked to run deploy's code and there is no deploy user."""


def shell_environment(source: Mapping[str, str], account: pwd.struct_passwd) -> dict[str, str]:
    """KEPT_ENV and LC_* from `source`, with PATH and `account`'s own variables."""
    env = {name: value for name, value in source.items()
           if name in KEPT_ENV or name.startswith("LC_")}
    env.update(PATH=SHELL_PATH, HOME=account.pw_dir, USER=account.pw_name,
               LOGNAME=account.pw_name, SHELL=account.pw_shell)
    return env


def deploy_account() -> pwd.struct_passwd:
    """The deploy user. Raises NoDeployUser on a host without one."""
    try:
        return pwd.getpwnam("deploy")
    except KeyError as e:
        raise NoDeployUser("running as root, deploy's code runs as the deploy user, "
                           "and this host has no deploy user") from e


def deploy_spawn_args(*, supplementary_groups: bool) -> dict[str, Any]:
    """subprocess arguments that run a command as the deploy shell would.

    As root they switch to deploy's uid and gid, and to deploy's
    supplementary groups (docker, for a hook) or none. Either way the
    command gets the shell's environment, no stdin, and its own session:
    without a controlling terminal it cannot push input into the terminal
    of a root operator (TIOCSTI). Raises NoDeployUser as root with no
    deploy user, rather than run the command as root.
    """
    if not running_as_root():
        return {"env": shell_environment(os.environ, pwd.getpwuid(os.getuid())),
                "stdin": subprocess.DEVNULL, "start_new_session": True}
    account = deploy_account()
    groups = os.getgrouplist(account.pw_name, account.pw_gid) if supplementary_groups else []
    return {"user": account.pw_uid, "group": account.pw_gid, "extra_groups": groups,
            "env": shell_environment(os.environ, account),
            "stdin": subprocess.DEVNULL, "start_new_session": True}


def run_as_deploy(argv: Sequence[str], cwd: Path, *, supplementary_groups: bool,
                  timeout: float | None = None,
                  check: bool = True) -> subprocess.CompletedProcess:
    """Run argv with deploy_spawn_args, capturing its output as text.

    In its own session, a terminal's Ctrl-C or hangup reaches only
    boxmunge, so whatever stops boxmunge here (an interrupt, a timeout, an
    error) first kills the command's whole process group: nothing it
    started keeps running after the project lock is released. Raises
    TimeoutExpired, CalledProcessError on a non-zero exit when `check`,
    NoDeployUser, or OSError when the command cannot start.
    """
    proc = subprocess.Popen(list(argv), shell=False, cwd=cwd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True,
                            **deploy_spawn_args(supplementary_groups=supplementary_groups))
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except BaseException:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # the group has already gone
        proc.wait()
        raise
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, proc.args, stdout, stderr)
    return subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
