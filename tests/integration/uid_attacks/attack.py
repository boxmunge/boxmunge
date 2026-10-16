"""Runs as root inside a throwaway container: a deploy-uid attacker plants a
link in a deploy-writable boxmunge directory, then root does an ordinary
boxmunge write there. Prints what happened to a root-only file as JSON.

Usage: attack.py <scenario>
"""
import io
import json
import os
import subprocess
import sys
import tempfile
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path("/opt/boxmunge")
SECRET = Path("/root/secret")


def as_deploy(*argv: str) -> None:
    subprocess.run(["setpriv", "--reuid", "deploy", "--regid", "deploy", "--init-groups", *argv],
                   check=True)


def setup() -> None:
    subprocess.run(["useradd", "-m", "-s", "/bin/sh", "deploy"], check=True)
    ROOT.mkdir(mode=0o755)
    for d in ("logs", "state", "projects", "config", "stashes"):
        (ROOT / d).mkdir()
        os.chown(ROOT / d, *_deploy())
    SECRET.write_text("ROOT-ONLY\n")
    SECRET.chmod(0o600)
    Path("/root").chmod(0o755)


def _deploy() -> tuple[int, int]:
    import pwd
    pw = pwd.getpwnam("deploy")
    return pw.pw_uid, pw.pw_gid


def swap_for_link(name: str):
    """Wrap mkstemp so deploy replaces the new temp with a link to SECRET."""
    real = tempfile.mkstemp

    def mkstemp(*a, **kw):
        fd, path = real(*a, **kw)
        as_deploy("sh", "-c", f'rm -f "{path}" && ln -s {SECRET} "{path}"')
        return fd, path
    return patch(name, side_effect=mkstemp)


def scenario(name: str) -> str:
    from boxmunge.paths import BoxPaths
    paths = BoxPaths(ROOT)
    if name == "log-active-link":
        as_deploy("ln", "-s", str(SECRET), str(paths.log_file))
        from boxmunge.log import log_operation
        log_operation("t", "root writes", paths)
    elif name == "log-archive-link":
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        entry = json.dumps({"ts": yesterday.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "msg": "old"})
        as_deploy("sh", "-c", f"echo '{entry}' > {paths.log_file}")
        archive = paths.logs / f"boxmunge.log.{yesterday.date().isoformat()}"
        as_deploy("ln", "-s", str(SECRET), str(archive))
        from boxmunge.log import log_operation
        log_operation("t", "root writes", paths)
    elif name == "lock-link":
        as_deploy("ln", "-s", str(SECRET), str(paths.project_lock_file("app")))
        from boxmunge.fileutil import project_lock
        with project_lock("app", paths):
            pass
    elif name == "atomic-write-swap":
        from boxmunge.fileutil import atomic_write_text
        with swap_for_link("boxmunge.fileutil.tempfile.mkstemp"):
            atomic_write_text(paths.state / "x.json", "{}", mode=0o644)
    elif name == "dump-temp-swap":

        from boxmunge import backup_dump
        paths.project_backups("app").mkdir(parents=True)
        os.chown(paths.project_backups("app"), *_deploy())
        os.chown(paths.project_dir("app"), *_deploy())

        def fake_run(project_dir, project, service, command, *, timeout, stdout, stderr):
            stdout.write(b"DUMP-OUTPUT\n")
            return subprocess.CompletedProcess([], 0, stderr=b"")
        with swap_for_link("boxmunge.backup_dump.tempfile.mkstemp"), \
             patch.object(backup_dump, "run_in_service", side_effect=fake_run), \
             patch("boxmunge.backup.platform_owner", return_value=_deploy()):
            backup_dump.execute_dump(paths, "app", "dump", "db")
    elif name == "stash-link":
        from boxmunge import stash
        fixed = datetime(2026, 1, 1, tzinfo=timezone.utc)
        target = paths.stashes / "boxmunge-stash-2026-01-01T000000.tar.gz"
        as_deploy("ln", "-s", str(SECRET), str(target))
        with patch.object(stash, "datetime", MagicMock(now=lambda tz=None: fixed)):
            stash.create_stash(paths)
    else:
        raise SystemExit(f"unknown scenario {name}")
    return "completed"


def main() -> None:
    setup()
    err = io.StringIO()
    with redirect_stderr(err):
        try:
            outcome = scenario(sys.argv[1])
        except Exception as e:  # the refusal is the expected outcome
            outcome = f"raised {type(e).__name__}: {e}"
    st = SECRET.stat()
    print(json.dumps({
        "outcome": outcome, "stderr": err.getvalue(),
        "secret": {"uid": st.st_uid, "gid": st.st_gid, "mode": oct(st.st_mode & 0o777),
                   "content": SECRET.read_bytes().decode(errors="replace")},
    }))


if __name__ == "__main__":
    main()
