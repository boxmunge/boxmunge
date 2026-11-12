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

import logging
import secrets
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any, NamedTuple

from boxmunge.docker_run import docker_env

_LOGGER = logging.getLogger("boxmunge")

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
# $1 is the pid file name. On stdout, the group it killed, and "unreaped"
# after it when their entries are still listed. What it says on stderr is
# the same for the same cause on every run (no pid, no file name): the
# health monitor alerts again whenever a failure's message changes.
_STOP_SCRIPT = r"""
pid=""
for d in /dev/shm /tmp; do
  if [ -r "$d/$1" ]; then read -r pid < "$d/$1"; pf="$d/$1"; break; fi
done
[ -n "$pid" ] || { echo "no record of the command's process group" >&2; exit 1; }
case "$pid" in
  *[!0-9]*) pid=0 ;;
esac
[ "$pid" -gt 1 ] || { echo "the pid record does not hold a process group id" >&2; exit 1; }
[ -r /proc/$$/stat ] || { echo "/proc is not readable" >&2; exit 1; }
# Whether the group has a member in a state other than $1: "Z" asks for
# one still running (a zombie has been killed), "" for any entry at all.
left() {
  for f in /proc/[0-9]*/stat; do
    read -r line < "$f" 2>/dev/null || continue
    set -- "$1" ${line##*) }
    [ "$4" = "$pid" ] && [ "$2" != "$1" ] && return 0
  done
  return 1
}
# `kill -9 -N`, not `kill -s KILL -N`: dash (Debian's sh) reads the latter's
# "-N" as an option and kills nothing.
kill -9 "-$pid" 2>/dev/null
running=1
for i in 1 2 3 4 5 6 7 8 9 10; do
  left Z || { running=0; break; }
  sleep 1 2>/dev/null
done
[ "$running" = 0 ] || { echo "the process group is still running after SIGKILL" >&2; exit 1; }
rm -f "$pf"
# Killed. An init reaps them at once; a PID 1 that is the app itself may
# never, and then their entries stay (each still counts as a process).
for i in 1 2 3; do
  left "" || { echo "$pid"; exit 0; }
  sleep 1 2>/dev/null
done
echo "$pid unreaped"
"""
_STOP_TIMEOUT = 60
# Said of a command that was killed but whose entries nothing reaps.
UNREAPED = ("its finished process entries remain until the container restarts, "
            "because the container runs without an init process")


class Stop(NamedTuple):
    """How stopping a command in its container went."""
    group: str | None  # the process group, killed and verified not running
    error: str | None  # without one, why that could not be confirmed
    unreaped: bool = False  # killed, but its entries are still listed


class ServiceCommandTimeout(Exception):
    """The command overran its budget.

    ``stopped_group`` is the process group killed and verified gone, or
    None with ``stop_error`` saying why that could not be confirmed.
    ``unreaped`` is whether the killed group's entries were left listed.
    """

    def __init__(self, timeout: float, stopped_group: str | None,
                 stop_error: str | None, unreaped: bool = False) -> None:
        self.timeout = timeout
        self.stopped_group = stopped_group
        self.stop_error = stop_error
        self.unreaped = unreaped
        if stopped_group is not None:
            outcome = f"it was stopped inside the container (process group {stopped_group})"
            if unreaped:
                outcome += f"; {UNREAPED}"
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


def _stop(exec_into: list[str], pid_name: str, cwd: Path | None = None) -> Stop:
    """Kill the command's process group in the container ``exec_into`` reaches.

    The pid file's name is random, so a container that has since been
    replaced under the same name holds no record and nothing in it is
    killed. A failure is worded the same on every run (see _STOP_SCRIPT):
    never the stop's own command, which holds that name.
    """
    cmd = [*exec_into, "sh", "-c", _STOP_SCRIPT, "boxmunge-stop", pid_name]
    try:
        result = subprocess.run(cmd, cwd=cwd, capture_output=True,
                                text=True, timeout=_STOP_TIMEOUT, env=docker_env())
    except subprocess.TimeoutExpired:
        return Stop(None, f"the stop did not finish in {_STOP_TIMEOUT}s")
    except OSError as e:
        return Stop(None, f"docker could not be run ({e.strerror or type(e).__name__})")
    group, *rest = result.stdout.split() or [""]
    if result.returncode != 0 or not group.isdigit() or rest not in ([], ["unreaped"]):
        return Stop(None, result.stderr.strip() or f"exit {result.returncode}")
    return Stop(group, None, unreaped=bool(rest))


def _run(exec_into: list[str], where: str, command: str, *, timeout: float,
         cwd: Path | None = None, **run_kwargs: Any) -> subprocess.CompletedProcess:
    """``sh -c command`` in the container ``exec_into`` reaches (``where``,
    in words), bounded by ``timeout``.

    Raises ServiceCommandTimeout when it overruns, after trying to kill it in
    the container. If boxmunge is interrupted meanwhile, the command is
    killed there too before the interruption propagates, and a stop that
    did not leave the container clean is logged, since nothing else will
    report it.
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
        stop = _stop(exec_into, pid_name, cwd)
        scope = {"component": "service-exec"}
        if stop.group is None:
            _LOGGER.warning("A command interrupted in %s may still be running there: "
                            "stopping it failed (%s)", where, stop.error, extra=scope)
        elif stop.unreaped:
            _LOGGER.warning("A command interrupted in %s was killed there; %s",
                            where, UNREAPED, extra=scope)
        raise


def run_in_service(
    project_dir: Path, project_name: str, service: str, command: str,
    *, timeout: float, compose_file: Path | None = None, **run_kwargs: Any,
) -> subprocess.CompletedProcess:
    """``sh -c command`` in the service's container, killably (see _run)."""
    return _run(_service_exec(project_dir, project_name, service, compose_file),
                f"service {service} of {project_name}", command,
                timeout=timeout, cwd=project_dir, **run_kwargs)


def run_in_container(
    container: str, command: str, *, timeout: float, env: Sequence[str] = (),
    **run_kwargs: Any,
) -> subprocess.CompletedProcess:
    """``sh -c command`` in that one container, killably (see _run), with
    each ``NAME=value`` of ``env`` added to its environment."""
    flags = [arg for variable in env for arg in ("-e", variable)]
    return _run(["docker", "exec", *flags, container], f"container {container}", command,
                timeout=timeout, **run_kwargs)
