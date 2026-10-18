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

`data chown <project> <service> <uid>:<gid>` is the one deliberate change of
a service's data ownership: it stops the service, gives its read-write
binds and named volumes to <uid>:<gid> through the helper, records that
user, and leaves the service stopped for the deploy that runs it as that
user (deploy refuses a user change over data the old user owns).
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import sys

from boxmunge.bind_sources import BindSourceError, project_rel, source_kind
from boxmunge.commands.deploy_checks import (
    persistent, service_mounts, volume_name, writable_by_a_container,
)
from boxmunge.compose_resolve import ComposeResolveError
from boxmunge.compose_guard import check_containers_start, start_containers_checked
from boxmunge.data_helper import (
    COMPOSE_VOLUME_LABEL, chown_under, compose_volume_labels, copy_into_volume, is_anonymous,
    run_helper, volume, volume_is_empty, volume_labels,
)
from boxmunge.docker import COMPOSE_PROJECT_LABEL
from boxmunge.docker_containers import container_mounts, project_containers
from boxmunge.docker_run import DockerError, run as _run
from boxmunge.fileutil import LockError, project_lock
from boxmunge.legacy_stage import legacy_stage_refusal
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.log import log_operation
from boxmunge.paths import BoxPaths
from boxmunge.release_target import production_target, resolved_services
from boxmunge.run_as import (
    MAX_ID, SOURCE_CHOWN, RunAsError, ServiceUser, numeric_ids, read_users, write_users,
)

_VOLUME_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,62}")
_STOP_TIMEOUT = 15
_USAGE = ("usage: boxmunge data adopt <project> <service>:<path> <name> | "
          "boxmunge data chown <project> <service> <uid>:<gid>")


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


def _refuse_if_migrating(paths: BoxPaths, project: str) -> None:
    block = is_blocked(project, paths)
    if block is not None and block.reason is BlockReason.MIGRATING:
        raise DataError(block.refuse_message)


def adopt_locked(paths: BoxPaths, project: str, service: str, path: str, name: str) -> None:
    """The adopt core. Caller holds the project lock. Raises DataError,
    DockerError or ComposeRefused (a DockerError) naming what failed."""
    _refuse_if_migrating(paths, project)
    refusal = legacy_stage_refusal(paths, project)
    if refusal is not None:
        raise DataError(refusal)
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


def _chown_mount(paths: BoxPaths, project: str, model: dict, m, ids: tuple[int, int]) -> bool:
    """Give one persistent mount to `ids`; False when it does not exist yet
    (mounting it would create it, unlabelled or root-owned). A bind is
    reached inside the helper with only the project dir mounted, so a link
    a container planted on the way leads nowhere on the host."""
    print(f"  Giving {m.source} to {ids[0]}:{ids[1]}...")
    if m.kind == "bind":
        project_dir = paths.project_dir(project)
        if not os.path.lexists(str(m.source)):
            return False
        holder = writable_by_a_container(project, str(m.source), below=True)
        if holder is not None:
            raise DataError(f"{m.source} lies inside {holder}, which a container of "
                            f"{project} mounts read-write; give {holder} itself to "
                            f"{ids[0]}:{ids[1]}, or stop mounting it read-write")
        rel = project_rel(str(m.source), project_dir)
        source_kind(project_dir, rel, create=False)
        chown_under(f"{project}-chown", project_dir, Path(rel), ids)
        return True
    name = volume_name(model, project, str(m.source))
    if volume_labels(name) is None:
        return False
    run_helper(f"{project}-chown", volume(name, "/x"), f"chown -R -h {ids[0]}:{ids[1]} /x")
    return True


def chown_locked(paths: BoxPaths, project: str, service: str, ids: tuple[int, int]) -> None:
    """Stop the service, chown its persistent mounts to `ids`, record the
    user. Caller holds the project lock. The service is left stopped: its
    next start (the deploy) runs it as `ids`. Raises DataError, DockerError,
    BindSourceError or RunAsError."""
    _refuse_if_migrating(paths, project)
    refusal = legacy_stage_refusal(paths, project)
    if refusal is not None:
        raise DataError(refusal)
    model, services = resolved_services(production_target(paths, project))
    if service not in services:
        raise DataError(f"{project} has no service {service}")
    mounts = persistent(service_mounts(services[service]))
    if not mounts:
        raise DataError(f"service {service} of {project} keeps no data in a read-write "
                        f"bind or a named volume; there is nothing to chown")
    users = read_users(paths, project)
    running = _running(project, service)
    if running:
        print(f"  Stopping {', '.join(running)}; it stays stopped until you deploy.")
        _run(["docker", "stop", "-t", str(_STOP_TIMEOUT), *running], capture=True)
    done = [m.target for m in mounts if _chown_mount(paths, project, model, m, ids)]
    image_user = users[service].image_user if service in users else ""
    users[service] = ServiceUser(f"{ids[0]}:{ids[1]}", SOURCE_CHOWN, image_user)
    write_users(paths, project, users)
    log_operation("data-chown", f"Gave {service}'s data to {ids[0]}:{ids[1]}", paths,
                  project=project, detail={"mounts": done})
    print(f"Done. Deploy {project} now: {service} runs as {ids[0]}:{ids[1]} from its "
          f"next start.")


def run_data_chown(paths: BoxPaths, project: str, service: str, spec: str) -> int:
    ids = numeric_ids(spec)
    if ids is None or not all(1 <= i <= MAX_ID for i in ids):
        print(f"ERROR: {spec!r} must be <uid>:<gid>, each between 1 and {MAX_ID} "
              f"(data chown never gives data to root)", file=sys.stderr)
        return 2
    try:
        with project_lock(project, paths):
            chown_locked(paths, project, service, ids)
    except (DataError, DockerError, LockError, BindSourceError, RunAsError,
            ComposeResolveError, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    return 0


def _usage_error(detail: str = "") -> None:
    print(f"ERROR: {detail}{_USAGE}", file=sys.stderr)
    sys.exit(2)


def cmd_data(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name
    if not args or args[0] not in ("adopt", "chown"):
        _usage_error()
    parsed = parse_args("data", args[1:], min_positional=3, max_positional=3)
    project = require_project_name("data", parsed.positional[0])
    if args[0] == "chown":
        sys.exit(run_data_chown(BoxPaths(), project, parsed.positional[1],
                                parsed.positional[2]))
    service, sep, path = parsed.positional[1].partition(":")
    if not sep or not service or not path.startswith("/"):
        _usage_error("the second argument is <service>:<absolute path in the container>; ")
    sys.exit(run_data_adopt(BoxPaths(), project, service, path, parsed.positional[2]))
