"""Run as real root by test_hook_as_deploy.py: deploy a hook, report what it saw.

A root-only file is open on fd 7, as a root caller's descriptors would be,
and the hook tries to read it through /proc/self/fd/7 and by name.
"""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from boxmunge.commands.deploy import run_pre_deploy_hook
from boxmunge.paths import BoxPaths

subprocess.run(["useradd", "--create-home", "deploy"], check=True)
secret = Path("/root/secret")
secret.write_text("ROOT-ONLY\n")
secret.chmod(0o600)
fd = os.open(secret, os.O_RDONLY)
os.dup2(fd, 7, inheritable=True)

paths = BoxPaths(root=Path("/tmp/bm"))
project = paths.project_dir("demo")
(project / "boxmunge-scripts").mkdir(parents=True)
hook = project / "boxmunge-scripts" / "pre-deploy.sh"
hook.write_text("""#!/bin/sh
out=/tmp/hook-report
{
  echo "uid=$(id -u) gid=$(id -g) groups=$(id -G)"
  echo "cwd=$(pwd)"
  echo "fd7=$(cat /proc/self/fd/7 2>/dev/null || echo closed)"
  echo "secret=$(cat /root/secret 2>/dev/null || echo denied)"
  echo "tty=$(tty -s && echo yes || echo no)"
  echo "own_session=$(python3 -c 'import os; print(os.getsid(0) == os.getppid())')"
  env | sort | sed 's/^/env:/'
} > "$out"
""")
hook.chmod(0o755)
for p in (paths.root, paths.projects, project):
    os.chown(p, 0, 0)  # root-owned like a sudo install could leave them; the hook only reads
os.environ.update(HOME="/root", USER="root", SUDO_USER="supervisor", BASH_ENV="/tmp/x",
                  PYTHONPATH=os.environ.get("PYTHONPATH", ""))
os.chmod("/tmp", 0o1777)
rc = run_pre_deploy_hook("demo", paths, {"deploy": {"pre_deploy": "boxmunge-scripts/pre-deploy.sh"}})
report = Path("/tmp/hook-report").read_text() if Path("/tmp/hook-report").exists() else ""


def interrupted_hook_survivors() -> list[str]:
    """Ctrl-C a deploy whose hook started a child: what is left running.
    The terminal signals the foreground group: boxmunge, not the hook's own
    session."""
    slow = project / "boxmunge-scripts" / "slow.sh"
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


survivors = interrupted_hook_survivors()
pw = __import__("pwd").getpwnam("deploy")
print(json.dumps({"rc": rc, "report": report, "deploy_uid": pw.pw_uid,
                  "deploy_gid": pw.pw_gid, "project": str(project), "survivors": survivors}))
sys.exit(0)
