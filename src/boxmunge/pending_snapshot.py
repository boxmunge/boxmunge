# SPDX-License-Identifier: Apache-2.0
"""A snapshot taken ahead of the next deploy, for it to pair with its rollback target.

`data chown` stops a service and leaves it stopped for the deploy that runs
it as its new user. When that service is the backup service, the deploy's
own pre-deploy dump (which runs in it) cannot be taken. data chown takes the
snapshot itself, while the service still runs, and records it here, in the
deploy state file, with the release it is of and the service it stopped.

The record holds only while that service has not run since: the next
pre-deploy step of that release uses it (deploy_steps), and recording that
deploy clears it (record_deploy_state). Any production start of the service
(compose_guard, the only way boxmunge starts containers) clears it first,
since from then on its data may change.
"""
from __future__ import annotations

from datetime import datetime, timezone

from boxmunge.log import log_operation
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError, read_state, write_state

KEY = "pending_snapshot"
_FIELDS = ("name", "taken_by", "service", "ref", "at")


def record_pending(paths: BoxPaths, project: str, name: str, taken_by: str,
                   service: str, containers: list[str]) -> None:
    state_path = paths.project_deploy_state(project)
    state = read_state(state_path)
    state[KEY] = {"name": name, "taken_by": taken_by, "service": service,
                  "containers": list(containers), "ref": str(state.get("current_ref", "")),
                  "at": datetime.now(timezone.utc).isoformat()}
    write_state(state_path, state)


def pending(paths: BoxPaths, project: str) -> dict | None:
    """The recorded snapshot, or None. Raises StateError for a record of
    another shape."""
    entry = read_state(paths.project_deploy_state(project)).get(KEY)
    if entry is None:
        return None
    if not (isinstance(entry, dict)
            and all(isinstance(entry.get(k), str) for k in _FIELDS)
            and isinstance(entry.get("containers"), list)
            and all(isinstance(c, str) for c in entry["containers"])):
        raise StateError(f"{paths.project_deploy_state(project)}: {KEY} is not a "
                         f"snapshot record: {entry!r}")
    return entry


def pending_for_live(paths: BoxPaths, project: str) -> dict | None:
    """The recorded snapshot when it is of the live release and still in
    backups/; otherwise None, saying why a recorded one is passed over."""
    entry = pending(paths, project)
    if entry is None:
        return None
    live = str(read_state(paths.project_deploy_state(project)).get("current_ref", ""))
    if entry["ref"] != live:
        print(f"  The snapshot {entry['name']} that {entry['taken_by']} took is of "
              f"release {entry['ref'] or 'none'}, not of the live {live}; not using it.")
        return None
    if not (paths.project_backups(project) / entry["name"]).exists():
        print(f"  WARN: The snapshot {entry['name']} that {entry['taken_by']} took is no "
              f"longer in backups/; not using it.")
        return None
    return entry


def spend_if_service_starts(paths: BoxPaths, project: str, services: list[str] | None,
                            component: str) -> None:
    """Before a production up of `services` (None: every service)."""
    entry = pending(paths, project)
    if entry is not None and (services is None or entry["service"] in services):
        _spend(paths, project, entry, component)


def spend_if_containers_start(paths: BoxPaths, project: str, names: list[str],
                              component: str) -> None:
    """Before a `docker start` of production's containers `names`."""
    entry = pending(paths, project)
    if entry is not None and set(entry["containers"]) & set(names):
        _spend(paths, project, entry, component)


def _spend(paths: BoxPaths, project: str, entry: dict, component: str) -> None:
    # Logged, not printed: the deploy that used the snapshot spends it here
    # too, and after any other start the next deploy simply dumps afresh.
    state_path = paths.project_deploy_state(project)
    state = read_state(state_path)
    state.pop(KEY, None)
    write_state(state_path, state)
    log_operation(component, f"{entry['service']} starts: the snapshot {entry['name']} "
                  f"that {entry['taken_by']} took is no longer kept for the next deploy",
                  paths, project=project)
