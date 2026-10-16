# SPDX-License-Identifier: Apache-2.0
"""boxmunge data — put a project's data where the platform can carry it.

`data adopt <project> <service>:<path> <name>` copies the service's
anonymous volume at <path> into a new named volume `<project>_<name>`,
labelled as Compose labels its own, so the next deploy adopts it instead of
starting the service on an empty volume. An anonymous volume survives only
because Compose hands it from a container to its replacement; a migration,
a `compose down -v` or a recreate elsewhere loses it.

The service's running containers are stopped for the copy and started
again afterwards, whatever happens, as staging's data copy does (the start
checks of compose_guard apply both before the stop and at the start). The
anonymous volume is left in place for the operator to remove once the
redeployed service runs on the named one.
"""
from __future__ import annotations

import re
import sys

from boxmunge.compose_guard import check_containers_start, start_containers_checked
from boxmunge.data_helper import (
    COMPOSE_VOLUME_LABEL, compose_volume_labels, copy_into_volume, is_anonymous,
    volume_is_empty, volume_labels,
)
from boxmunge.docker import COMPOSE_PROJECT_LABEL
from boxmunge.docker_containers import container_mounts, project_containers
from boxmunge.docker_run import DockerError, run as _run
from boxmunge.fileutil import LockError, project_lock
from boxmunge.log import log_operation
from boxmunge.paths import BoxPaths

_VOLUME_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,62}")
_STOP_TIMEOUT = 15
_USAGE = "usage: boxmunge data adopt <project> <service>:<path> <name>"


class DataError(Exception):
    """A data command refused, saying why and what to do."""


def _running(project: str, service: str) -> list[str]:
    return [c.name for c in project_containers(project)
            if c.service == service and c.running and not c.oneoff]


def _anonymous_source(project: str, service: str, path: str) -> str:
    names = {str(m.get("Name")) for _c, svc, m in container_mounts(project)
             if svc == service and m.get("Type") == "volume" and m.get("Destination") == path}
    if not names:
        raise DataError(f"service {service} of {project} has no volume mounted at {path}")
    if len(names) != 1:
        raise DataError(f"service {service} of {project} has several volumes at {path} "
                        f"({', '.join(sorted(names))}), one per replica; scale it to one "
                        f"replica and remove the others' containers first")
    source = names.pop()
    labels = volume_labels(source)
    if labels is None:
        raise DataError(f"volume {source} at {path} of service {service} does not exist; "
                        f"copying from it would create an empty one")
    if not is_anonymous(labels, source):
        raise DataError(f"{path} of service {service} is already a named volume ({source}); "
                        f"there is nothing to adopt")
    return source


def _prepare_target(project: str, name: str) -> tuple[str, bool]:
    """The target volume's name, and whether it must be created."""
    target = f"{project}_{name}"
    labels = volume_labels(target)
    if labels is None:
        return target, True
    if (labels.get(COMPOSE_PROJECT_LABEL), labels.get(COMPOSE_VOLUME_LABEL)) != (project, name):
        raise DataError(f"volume {target} exists but is not labelled for Compose as "
                        f"{project}'s {name!r}; remove it or choose another name")
    if not volume_is_empty(f"{project}-adopt", target):
        raise DataError(f"volume {target} already exists and holds data; it was not "
                        f"changed. Remove it first if it is a leftover, or choose another name")
    return target, False


def _start_again(paths: BoxPaths, project: str, service: str, stopped: list[str]) -> None:
    try:
        start_containers_checked(paths, project, stopped, component="data-adopt")
    except DockerError as e:
        raise DataError(f"SERVICE {service} IS DOWN: its containers were stopped for the "
                        f"copy and starting them again failed: {e}. Start them with: "
                        f"docker start {' '.join(stopped)}") from e


def _remove_partial(target: str) -> None:
    """The adopt failed before the copy completed. The target, created by
    adopt or verified empty, may hold part of the copy under the labels that
    make the next deploy adopt it without a word, so it goes."""
    try:
        _run(["docker", "volume", "rm", target], capture=True)
    except DockerError as e:
        print(f"  WARN: the adopt failed and {target} may hold part of the copy, but "
              f"removing it failed: {e}. Remove it before deploying: docker volume rm "
              f"{target}",
              file=sys.stderr)


def adopt_locked(paths: BoxPaths, project: str, service: str, path: str, name: str) -> None:
    """The adopt core. Caller holds the project lock. Raises DataError,
    DockerError or ComposeRefused (a DockerError) naming what failed."""
    if not _VOLUME_NAME.fullmatch(name):
        raise DataError(f"volume name {name!r} must be lower-case letters, digits, '_', "
                        f"'.' or '-', starting with a letter or digit, at most 63 characters")
    source = _anonymous_source(project, service, path)
    target, create = _prepare_target(project, name)
    stopped = _running(project, service)
    if stopped:
        check_containers_start(paths, project, component="data-adopt")
    if create:
        _run(["docker", "volume", "create", *compose_volume_labels(project, name), target],
             capture=True)
    try:
        try:
            if stopped:
                print(f"  Stopping {', '.join(stopped)} for the copy...")
                _run(["docker", "stop", "-t", str(_STOP_TIMEOUT), *stopped], capture=True)
            print(f"  Copying {path} ({source[:12]}) into {target}...")
            copy_into_volume(f"{project}-adopt", source, target)
        except BaseException:
            _remove_partial(target)
            raise
    finally:
        if stopped:
            _start_again(paths, project, service, stopped)
    log_operation("data-adopt", f"Copied {service}:{path} into volume {target}", paths,
                  project=project, detail={"source": source, "target": target})
    print(f"Adopted {service}:{path} as volume {target}. Now add `{name}:{path}` to the "
          f"service's volumes (and `{name}: {{}}` under top-level volumes) and deploy. "
          f"(For a writable.persistent entry instead, which the platform names "
          f"{project}_<entry name>, adopt with the name {project}_<entry name>.) The "
          f"anonymous volume {source} is left in place; remove it once the service runs "
          f"on {target}.")


def run_data_adopt(paths: BoxPaths, project: str, service: str, path: str, name: str) -> int:
    try:
        with project_lock(project, paths):
            adopt_locked(paths, project, service, path, name)
    except (DataError, DockerError, LockError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_data(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name
    if not args or args[0] != "adopt":
        print(f"ERROR: {_USAGE}", file=sys.stderr)
        sys.exit(2)
    parsed = parse_args("data", args[1:], min_positional=3, max_positional=3)
    project = require_project_name("data", parsed.positional[0])
    service, sep, path = parsed.positional[1].partition(":")
    if not sep or not service or not path.startswith("/"):
        print(f"ERROR: the second argument is <service>:<absolute path in the container>; "
              f"{_USAGE}", file=sys.stderr)
        sys.exit(2)
    sys.exit(run_data_adopt(BoxPaths(), project, service, path, parsed.positional[2]))
