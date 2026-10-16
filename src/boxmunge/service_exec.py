# SPDX-License-Identifier: Apache-2.0
"""Run a backup or restore command inside a project service, killably.

Killing the `docker compose exec` client (on a timeout, or when boxmunge is
itself interrupted) does not stop what it started inside the container. A
hung pg_dump left running keeps its database locks and blocks the next
restore, and nightly runs would pile up more of them.

So the command runs under a small sh wrapper that leads its own process
group (`docker exec` makes it a session leader; elsewhere it re-executes
itself under setsid) and records that group's id in a pid file in /dev/shm
or /tmp. To stop it, a second exec kills the whole group and then checks
/proc until no live member is left. Anything that cannot be verified (no
pid file, unreadable /proc, a member that will not die, e.g. one running as
another uid) is reported as possibly still running, never as stopped.
A process that leaves the group itself (its own setsid) escapes both, so
the report names the group that was killed.
"""

from __future__ import annotations

import secrets
import subprocess
from pathlib import Path
from typing import Any

# $0 is this script, $1 the pid file name, $2 the command. No output on
# stdout, which carries the dump.
_WRAPPER = r"""
read -r stat < /proc/$$/stat 2>/dev/null || stat=""
set -- "$0" "$1" "$2" ${stat##*) }
if [ "$6" != "$$" ] && command -v setsid >/dev/null 2>&1 && [ -z "$BOXMUNGE_SETSID" ]; then
  BOXMUNGE_SETSID=1 exec setsid sh -c "$1" "$1" "$2" "$3"
fi
pf=""
if [ "$6" = "$$" ]; then
  for d in /dev/shm /tmp; do
    if (umask 077; echo $$ > "$d/$2") 2>/dev/null; then pf="$d/$2"; break; fi
  done
fi
sh -c "$3"
rc=$?
[ -n "$pf" ] && rm -f "$pf"
exit $rc
"""
# $1 is the pid file name.
_STOP_SCRIPT = r"""
pid=""
for d in /dev/shm /tmp; do
  if [ -r "$d/$1" ]; then read -r pid < "$d/$1"; pf="$d/$1"; break; fi
done
[ -n "$pid" ] || { echo "no record of the command's process group" >&2; exit 1; }
case "$pid" in
  *[!0-9]*) echo "pid record $pf holds '$pid', not a process group id" >&2; exit 1 ;;
esac
[ "$pid" -gt 1 ] || { echo "pid record $pf holds '$pid', not a process group id" >&2; exit 1; }
[ -r /proc/$$/stat ] || { echo "/proc is not readable" >&2; exit 1; }
alive() {
  for f in /proc/[0-9]*/stat; do
    read -r line < "$f" 2>/dev/null || continue
    set -- ${line##*) }
    [ "$3" = "$pid" ] && [ "$1" != Z ] && return 0
  done
  return 1
}
# `kill -9 -N`, not `kill -s KILL -N`: dash (Debian's sh) reads the latter's
# "-N" as an option and kills nothing.
kill -9 "-$pid" 2>/dev/null
for i in 1 2 3 4 5 6 7 8 9 10; do
  alive || { rm -f "$pf"; echo "$pid"; exit 0; }
  sleep 1 2>/dev/null
done
echo "process group $pid is still running after SIGKILL" >&2
exit 1
"""
_STOP_TIMEOUT = 60


class ServiceCommandTimeout(Exception):
    """The command overran its budget.

    ``stopped_group`` is the process group killed and verified gone, or
    None with ``stop_error`` saying why that could not be confirmed.
    """

    def __init__(self, timeout: float, stopped_group: str | None,
                 stop_error: str | None) -> None:
        self.timeout = timeout
        self.stopped_group = stopped_group
        self.stop_error = stop_error
        if stopped_group is not None:
            outcome = f"it was stopped inside the container (process group {stopped_group})"
        else:
            outcome = (f"stopping it inside the container FAILED ({stop_error}), "
                       "so it may still be running there")
        super().__init__(f"timed out after {timeout}s; {outcome}")


def _exec(project_name: str, service: str, argv: list[str]) -> list[str]:
    return ["docker", "compose", "-f", "compose.yml", "-p", project_name,
            "exec", "-T", service, *argv]


def _stop(project_dir: Path, project_name: str, service: str,
          pid_name: str) -> tuple[str | None, str | None]:
    """Kill the command's process group in the container.

    Returns (group id, None) once the group is verified gone, else
    (None, why not).
    """
    cmd = _exec(project_name, service, ["sh", "-c", _STOP_SCRIPT, "boxmunge-stop", pid_name])
    try:
        result = subprocess.run(cmd, cwd=project_dir, capture_output=True,
                                text=True, timeout=_STOP_TIMEOUT)
    except (subprocess.TimeoutExpired, OSError) as e:
        return None, str(e)
    group = result.stdout.strip()
    if result.returncode != 0 or not group.isdigit():
        return None, result.stderr.strip() or f"exit {result.returncode}"
    return group, None


def run_in_service(
    project_dir: Path, project_name: str, service: str, command: str,
    *, timeout: float, **run_kwargs: Any,
) -> subprocess.CompletedProcess:
    """``sh -c command`` in the service, bounded by ``timeout``.

    Raises ServiceCommandTimeout when it overruns, after trying to kill it in
    the container. If boxmunge is interrupted meanwhile, the command is
    killed there too before the interruption propagates.
    """
    pid_name = f"boxmunge-exec-{secrets.token_hex(16)}.pid"
    cmd = _exec(project_name, service, ["sh", "-c", _WRAPPER, _WRAPPER, pid_name, command])
    try:
        return subprocess.run(cmd, cwd=project_dir, timeout=timeout, **run_kwargs)
    except subprocess.TimeoutExpired as e:
        raise ServiceCommandTimeout(
            timeout, *_stop(project_dir, project_name, service, pid_name)) from e
    except OSError:
        raise  # nothing started
    except BaseException:
        _stop(project_dir, project_name, service, pid_name)
        raise
