# SPDX-License-Identifier: Apache-2.0
"""Run a command inside a project's container, killably.

Killing the `docker exec` client (on a timeout, or when boxmunge is itself
interrupted) does not stop what it started inside the container. A hung
pg_dump left running keeps its database locks and blocks the next restore,
and nightly runs would pile up more of them; a hung smoke script would pile
up one more copy on every health tick.

A backup or restore command runs in its service (`docker compose exec`,
run_in_service). A smoke runs in one named container (`docker exec`,
run_in_container), so every replica is reached and no compose file is read.

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
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from boxmunge.docker_run import docker_env

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


def _service_exec(project_dir: Path, project_name: str, service: str,
                  compose_file: Path | None = None) -> list[str]:
    """The exec into a service, to be followed by the command's argv.

    `compose_file` names the compose file of the release the containers run
    when it is not the project dir's (during an open install); paths in it
    still resolve against the project dir."""
    files = (["-f", "compose.yml"] if compose_file is None else
             ["--project-directory", str(project_dir), "-f", str(compose_file)])
    return ["docker", "compose", *files, "-p", project_name, "exec", "-T", service]


def _stop(exec_into: list[str], pid_name: str,
          cwd: Path | None = None) -> tuple[str | None, str | None]:
    """Kill the command's process group in the container ``exec_into`` reaches.

    Returns (group id, None) once the group is verified gone, else
    (None, why not). The pid file's name is random, so a container that has
    since been replaced under the same name holds no record and nothing in
    it is killed.
    """
    cmd = [*exec_into, "sh", "-c", _STOP_SCRIPT, "boxmunge-stop", pid_name]
    try:
        result = subprocess.run(cmd, cwd=cwd, capture_output=True,
                                text=True, timeout=_STOP_TIMEOUT, env=docker_env())
    except (subprocess.TimeoutExpired, OSError) as e:
        return None, str(e)
    group = result.stdout.strip()
    if result.returncode != 0 or not group.isdigit():
        return None, result.stderr.strip() or f"exit {result.returncode}"
    return group, None


def _run(exec_into: list[str], command: str, *, timeout: float,
         cwd: Path | None = None, **run_kwargs: Any) -> subprocess.CompletedProcess:
    """``sh -c command`` in the container ``exec_into`` reaches, bounded by
    ``timeout``.

    Raises ServiceCommandTimeout when it overruns, after trying to kill it in
    the container. If boxmunge is interrupted meanwhile, the command is
    killed there too before the interruption propagates.
    """
    pid_name = f"boxmunge-exec-{secrets.token_hex(16)}.pid"
    cmd = [*exec_into, "sh", "-c", _WRAPPER, _WRAPPER, pid_name, command]
    try:
        return subprocess.run(cmd, cwd=cwd, timeout=timeout, env=docker_env(), **run_kwargs)
    except subprocess.TimeoutExpired as e:
        raise ServiceCommandTimeout(timeout, *_stop(exec_into, pid_name, cwd)) from e
    except OSError:
        raise  # nothing started
    except BaseException:
        _stop(exec_into, pid_name, cwd)
        raise


def run_in_service(
    project_dir: Path, project_name: str, service: str, command: str,
    *, timeout: float, compose_file: Path | None = None, **run_kwargs: Any,
) -> subprocess.CompletedProcess:
    """``sh -c command`` in the service's container, killably (see _run)."""
    return _run(_service_exec(project_dir, project_name, service, compose_file), command,
                timeout=timeout, cwd=project_dir, **run_kwargs)


def run_in_container(
    container: str, command: str, *, timeout: float, env: Sequence[str] = (),
    **run_kwargs: Any,
) -> subprocess.CompletedProcess:
    """``sh -c command`` in that one container, killably (see _run), with
    each ``NAME=value`` of ``env`` added to its environment."""
    flags = [arg for variable in env for arg in ("-e", variable)]
    return _run(["docker", "exec", *flags, container], command, timeout=timeout, **run_kwargs)
