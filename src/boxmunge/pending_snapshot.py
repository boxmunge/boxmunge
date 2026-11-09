# SPDX-License-Identifier: Apache-2.0
"""A snapshot taken ahead of the next deploy, for it to pair with its rollback target.

`data chown` stops a service and leaves it stopped for the deploy that runs
it as its new user. When that service is the backup service, the deploy's
own pre-deploy dump (which runs in it) cannot be taken. data chown takes the
snapshot itself, while the service still runs, and records it here, in the
deploy state file, once the stop succeeded: with the release it is of, the
service and the containers it stopped.

The record is trusted only as long as Docker shows the service has not run
since: it is checked when it is used (pending_for_live). A start boxmunge
did not make (a restart policy after a reboot, a plain `docker start`), a
recreate or a removal of its containers drops it, and the deploy takes its
own snapshot as usual. Recording a deploy clears it (record_deploy_state).
"""
from __future__ import annotations

from datetime import datetime, timezone

from boxmunge import docker_containers
from boxmunge.docker_run import DockerError
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError, read_state, write_state

KEY = "pending_snapshot"
_FIELDS = ("name", "taken_by", "service", "ref", "at")


def record_pending(paths: BoxPaths, project: str, name: str, taken_by: str,
                   service: str, containers: list[str]) -> None:
    """Record `name` for the next deploy. Only after `containers` (the
    service's, stopped by the caller) are stopped: the time recorded is
    what their next start is compared with."""
    if not containers:
        raise ValueError(f"{project}: a pending snapshot records the containers stopped; "
                         f"none was named")
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
            and isinstance(entry.get("containers"), list) and entry["containers"]
            and all(isinstance(c, str) for c in entry["containers"])):
        raise StateError(f"{paths.project_deploy_state(project)}: {KEY} is not a "
                         f"snapshot record: {entry!r}")
    try:
        datetime.fromisoformat(entry["at"])
    except ValueError as e:
        raise StateError(f"{paths.project_deploy_state(project)}: {KEY} has an "
                         f"unreadable time: {entry['at']!r}") from e
    return entry


def pending_for_live(paths: BoxPaths, project: str) -> dict | None:
    """The recorded snapshot when it still holds the data the next deploy
    would dump; otherwise None, saying why. A record shown stale (another
    release, gone from backups/, the service has run since) is dropped. When
    Docker cannot be asked, it is not used and kept for a later check."""
    entry = pending(paths, project)
    if entry is None:
        return None
    what = f"The snapshot {entry['name']} that {entry['taken_by']} took"
    live = str(read_state(paths.project_deploy_state(project)).get("current_ref", ""))
    try:
        stale = (f"it is of release {entry['ref'] or 'none'}, not of the live {live}"
                 if entry["ref"] != live else
                 "it is no longer in backups/"
                 if not (paths.project_backups(project) / entry["name"]).exists() else
                 _has_run_since(project, entry))
    except DockerError as e:
        print(f"  WARN: {what} is not used: whether {entry['service']} has run since it "
              f"was taken cannot be told ({e}).")
        return None
    if stale:
        drop(paths, project)
        print(f"  {what} is not used, and is dropped: {stale}.")
        return None
    return entry


def _has_run_since(project: str, entry: dict) -> str | None:
    """Why the service may have changed its data since the record, or None."""
    at = datetime.fromisoformat(entry["at"])
    states = docker_containers.start_states(project)
    gone = sorted(set(entry["containers"]) - set(states))
    if gone:
        return (f"{', '.join(gone)} of {entry['service']} no longer exists (removed or "
                f"recreated), so it may have run since")
    for name, st in sorted(states.items()):
        if st.service != entry["service"]:
            continue
        if st.running:
            return f"{entry['service']} is running again ({name})"
        if st.started_at > at:
            return (f"{entry['service']} has run since ({name} started at "
                    f"{st.started_at.isoformat(timespec='seconds')})")
    return None


def drop(paths: BoxPaths, project: str) -> None:
    state_path = paths.project_deploy_state(project)
    state = read_state(state_path)
    if state.pop(KEY, None) is not None:
        write_state(state_path, state)


def age(entry: dict) -> str:
    """How long ago the snapshot was recorded, for an operator to judge."""
    seconds = max(0, int((datetime.now(timezone.utc)
                          - datetime.fromisoformat(entry["at"])).total_seconds()))
    hours, rest = divmod(seconds, 3600)
    if hours >= 48:
        return f"{hours // 24} days"
    if hours:
        return f"{hours} h {rest // 60} min"
    return f"{rest // 60} min" if rest >= 60 else f"{rest} s"
