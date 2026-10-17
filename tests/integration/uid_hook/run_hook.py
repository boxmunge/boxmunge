"""Run as real root by test_hook_as_deploy.py: deploy as an operator's sudo would.

Root installs a release, keeps it as the previous one and installs the next,
running the release's pre-deploy hook, which writes a build output into the
release, and reports what it saw. A root-only file is open on fd 7, as a
root caller's descriptors would be, and the hook tries to read it through
/proc/self/fd/7 and by name. Last, Ctrl-C reaches a deploy whose hook
started a child.
"""
import json
import os
import pwd
import signal
import subprocess
import sys
import time
from pathlib import Path

from boxmunge.commands.deploy import run_pre_deploy_hook
from boxmunge.paths import BoxPaths
from boxmunge.release import install_release, mark_live
from boxmunge.release_keep import keep_previous_release_txn
from boxmunge.release_txn import InstallTxn

HOOK = """#!/bin/sh
set -e
echo building > app/build-info.txt
{
  echo "uid=$(id -u) gid=$(id -g) groups=$(id -G)"
  echo "cwd=$(pwd)"
  echo "fd7=$(cat /proc/self/fd/7 2>/dev/null || echo closed)"
  echo "secret=$(cat /root/secret 2>/dev/null || echo denied)"
  echo "tty=$(tty -s && echo yes || echo no)"
  echo "own_session=$(python3 -c 'import os; print(os.getsid(0) == os.getppid())')"
  env | sort | sed 's/^/env:/'
} > /tmp/hook-report
"""
MANIFEST = {"deploy": {"pre_deploy": "boxmunge-scripts/pre-deploy.sh"}}

subprocess.run(["useradd", "--create-home", "deploy"], check=True)
deploy = pwd.getpwnam("deploy")
secret = Path("/root/secret")
secret.write_text("ROOT-ONLY\n")
secret.chmod(0o600)
os.dup2(os.open(secret, os.O_RDONLY), 7, inheritable=True)
os.chmod("/tmp", 0o1777)
os.environ.update(HOME="/root", USER="root", SUDO_USER="supervisor", BASH_ENV="/tmp/x")

paths = BoxPaths(root=Path("/tmp/bm"))
project = paths.project_dir("demo")
paths.projects.mkdir(parents=True)
os.chown(paths.projects, deploy.pw_uid, deploy.pw_gid)  # as install.sh leaves it


def release(name: str) -> Path:
    tree = Path("/tmp/releases") / name
    (tree / "boxmunge-scripts").mkdir(parents=True)
    (tree / "app" / "static").mkdir(parents=True)
    (tree / "app" / "index.html").write_text(f"{name}\n")
    (tree / "boxmunge-scripts" / "pre-deploy.sh").write_text(HOOK)
    return tree


def txn(ref: str, replaced: str | None) -> InstallTxn:
    return InstallTxn(id=ref, source="bundle", ref=ref, replaced_ref=replaced, staged_id=None,
                      snapshot="", phase="committed", expect={}, previous_before=None,
                      had_previous=False, touched="", started_at="2026-10-17T00:00:00+00:00")


def not_deploys() -> list[str]:
    """Everything under the project directory that deploy does not own."""
    found = []
    for root, dirs, files in os.walk(project):
        for name in [*dirs, *files]:
            st = os.lstat(os.path.join(root, name))
            if (st.st_uid, st.st_gid) != (deploy.pw_uid, deploy.pw_gid):
                found.append(f"{os.path.join(root, name)} {st.st_uid}:{st.st_gid}")
    return found


rcs = []
install_release(release("one"), project)  # a first deploy, by root
mark_live(paths, "demo", "one")
rcs.append(run_pre_deploy_hook("demo", paths, MANIFEST))
keep_previous_release_txn(paths, "demo", txn("two", "one"), None)
install_release(release("two"), project)
mark_live(paths, "demo", "two")
rcs.append(run_pre_deploy_hook("demo", paths, MANIFEST))
report = Path("/tmp/hook-report").read_text() if Path("/tmp/hook-report").exists() else ""
build_info = project / "app" / "build-info.txt"
build_output = build_info.read_text() if build_info.exists() else ""


def interrupted_hook_survivors() -> list[str]:
    """Ctrl-C a deploy whose hook started a child: what is left running.
    The terminal signals the foreground group: boxmunge, not the hook's own
    session."""
    slow = Path("/tmp/slow.sh")
    slow.write_text("#!/bin/sh\nsleep 3001 &\nsleep 3002\n")
    slow.chmod(0o755)
    pid = os.fork()
    if pid == 0:
        os.setpgid(0, 0)
        try:
            run_pre_deploy_hook("demo", paths, {"deploy": {"pre_deploy": str(slow)}})
        except KeyboardInterrupt:
            os._exit(0)
        os._exit(1)
    time.sleep(2)
    os.killpg(pid, signal.SIGINT)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0, "the deploy was not interrupted"
    time.sleep(0.5)
    left = []
    for entry in Path("/proc").iterdir():
        try:
            cmd = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode()
        except OSError:
            continue
        if "sleep 300" in cmd:
            left.append(cmd)
    return left


owners = not_deploys()
survivors = interrupted_hook_survivors()
print(json.dumps({"rcs": rcs, "report": report, "build_output": build_output,
                  "not_deploys": owners, "deploy_uid": deploy.pw_uid,
                  "deploy_gid": deploy.pw_gid, "project": str(project),
                  "survivors": survivors}))
sys.exit(0)
