# SPDX-License-Identifier: Apache-2.0
"""The snapshot `pause` takes before it stops a project.

A paused project's containers are stopped, so a deploy that ends the pause
(`resume --no-start`, commands/deploy_handover) has nothing to run its
pre-deploy dump in, and its rollback could not restore data. Pause takes
the snapshot first, while the project still runs, and records it once the
stop succeeded (pending_snapshot): that deploy uses it as its pre-deploy
snapshot while Docker shows the backup service has not run since. A plain
`resume` starts the service, which makes the record stale; it is dropped
when it is next looked at.

The pause record names the snapshot from the start (pause.write_paused_state),
so when the stop fails and the pause is left incomplete, the run of `pause`
that finishes it still pairs it, if the service has not run since
(for_finishing).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from boxmunge.backup import BackupKind, resolve_backup_service
from boxmunge.backup_source import backup_source
from boxmunge.commands.backup_cmd import take_snapshot
from boxmunge.commands.health_state import is_monitor_stopped
from boxmunge.cve.quarantine import is_quarantined
from boxmunge import docker_containers
from boxmunge.data_dirs import ReleaseStateError
from boxmunge.manifest import ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.pause import read_paused_state, record_pause_snapshot
from boxmunge.pending_snapshot import (
    age, has_run_since, pending, pending_for_live, record_pending,
)
from boxmunge.state import StateError

TAKEN_BY = "pause"
NO_SNAPSHOT_COST = ("a deploy that ends this pause (`resume --no-start`) then cannot roll "
                    "its data back")


class PauseRefused(Exception):
    """The snapshot could not be taken: nothing was changed."""


@dataclass(frozen=True)
class PauseSnapshot:
    name: str
    service: str            # the backup service
    containers: list[str]   # its containers, running when the snapshot was taken
    at: str                 # when the dump began (ISO, UTC)

    def as_record(self) -> dict[str, Any]:
        return {"name": self.name, "service": self.service,
                "containers": list(self.containers), "at": self.at}

    @classmethod
    def from_record(cls, doc: Any, where: str) -> PauseSnapshot:
        """Raises StateError for a record of another shape."""
        try:
            if not (isinstance(doc, dict) and isinstance(doc["containers"], list)
                    and all(isinstance(doc[k], str) for k in ("name", "service", "at"))
                    and all(isinstance(c, str) for c in doc["containers"])):
                raise TypeError("wrong field types")
            datetime.fromisoformat(doc["at"])
        except (KeyError, TypeError, ValueError) as e:
            raise StateError(f"{where}: snapshot is not a pause snapshot record "
                             f"({e}): {doc!r}") from e
        return cls(doc["name"], doc["service"], list(doc["containers"]), doc["at"])


def _skip(paths: BoxPaths, project: str, no_snapshot: bool) -> str | None:
    """Why no snapshot is taken, before the backup is looked at (the line
    both the prompt and the pause print), or None."""
    if no_snapshot:
        return f"No snapshot (--no-snapshot): {NO_SNAPSHOT_COST}"
    stopped = ("is CVE-quarantined" if is_quarantined(project, paths) else
               "was stopped by the health monitor" if is_monitor_stopped(project, paths)
               else None)
    if stopped is not None:
        return f"No snapshot: {project} {stopped}, so nothing runs to dump; {NO_SNAPSHOT_COST}"
    return None


_NO_BACKUP = "No snapshot: backup.type is none, so there is no data backup to take"


def _no_backup(manifest: dict | None) -> bool:
    return manifest is not None and manifest.get("backup", {}).get("type", "none") == "none"


def plan_line(paths: BoxPaths, project: str, no_snapshot: bool) -> str:
    """The confirmation prompt's line about the snapshot. A backup source
    or pairing that cannot be read is the pause's to refuse, under the lock."""
    try:
        kept = pending(paths, project)
    except StateError:
        kept = None
    if kept is not None:
        return (f"The snapshot {kept['name']} that {kept['taken_by']} took stays the "
                f"pre-deploy snapshot while {kept['service']} has not run since; no new "
                f"one is taken")
    skip = _skip(paths, project, no_snapshot)
    if skip is not None:
        return skip
    try:
        if _no_backup(backup_source(paths, project).manifest):
            return _NO_BACKUP
    except (ManifestError, ReleaseStateError):
        pass
    return ("A data snapshot is taken first, for the deploy that ends the pause to roll "
            "back to (--no-snapshot skips it, e.g. in an emergency)")


def take(paths: BoxPaths, project: str, no_snapshot: bool) -> PauseSnapshot | None:
    """Snapshot the running project. None when there is nothing to take
    (--no-snapshot, backup.type none, or nothing runs: a quarantined or
    monitor-stopped project). Raises PauseRefused, DockerError, ManifestError,
    ReleaseStateError, StateError.

    A snapshot already paired with the next deploy (`data chown` stopped the
    backup service after taking it) is kept while Docker shows that service
    has not run since: it holds the data as it was before the change, and a
    dump now would have nothing to run in."""
    kept = pending_for_live(paths, project)
    if kept is not None:
        print(f"  The snapshot {kept['name']} that {kept['taken_by']} took {age(kept)} ago "
              f"stays the next deploy's pre-deploy snapshot: {kept['service']} has not run "
              f"since. No new one is taken.")
        return None
    skip = _skip(paths, project, no_snapshot)
    if skip is not None:
        print(f"  {skip}.")
        return None
    source = backup_source(paths, project)
    if source.manifest is None:
        raise PauseRefused(f"no snapshot can be taken before the pause: {source.skip}. "
                           f"Nothing was changed. Add --no-snapshot to pause without one "
                           f"({NO_SNAPSHOT_COST})")
    if _no_backup(source.manifest):
        print(f"  {_NO_BACKUP}.")
        return None
    service = resolve_backup_service(source.manifest)
    running = [c.name for c in docker_containers.project_containers(project)
               if c.service == service and c.running and not c.oneoff]
    print("  Taking a snapshot before pausing...")
    at = datetime.now(timezone.utc).isoformat()
    rc, name = take_snapshot(project, paths, BackupKind.PREPAUSE, source.manifest,
                             source.compose_file)
    if rc != 0 or name is None:
        raise PauseRefused(f"the snapshot before the pause was not taken (the backup said "
                           f"why above), so nothing was changed. Fix the backup and pause "
                           f"again, or add --no-snapshot to pause without one "
                           f"({NO_SNAPSHOT_COST})")
    return PauseSnapshot(name, service, running, at)


def for_finishing(paths: BoxPaths, project: str, no_snapshot: bool) -> PauseSnapshot | None:
    """The snapshot for the run of `pause` that finishes an incomplete one:
    the one the pause took first, while Docker shows its service has not run
    since (the failed stop stopped it, or the failure came after); else, if
    the service still runs, a new one (take), recorded in the pause record
    in its place; else none. A pause that took none takes none now. Raises
    as take does."""
    where = str(paths.project_paused_state(project))
    recorded = (read_paused_state(project, paths) or {}).get("snapshot")
    if recorded is None:
        return None
    first = PauseSnapshot.from_record(recorded, where)
    if not first.containers:
        print(f"  The snapshot {first.name} taken when this pause began stays in backups/ "
              f"for a manual restore: {first.service} was not running when it was taken, "
              f"so whether it runs before the next deploy cannot be told.")
        return None
    stale = has_run_since(project, first.as_record())
    if stale is None:
        print(f"  The snapshot {first.name} taken when this pause began is kept: "
              f"{first.service} has not run since.")
        return first
    states = docker_containers.start_states(project)
    if not no_snapshot and any(st.service == first.service and st.running
                               for st in states.values()):
        print(f"  The snapshot {first.name} taken when this pause began is not used "
              f"({stale}); a new one is taken.")
        fresh = take(paths, project, no_snapshot)
        if fresh is not None:
            record_pause_snapshot(project, paths, fresh.as_record())
        return fresh
    print(f"  The snapshot {first.name} taken when this pause began stays in backups/ "
          f"for a manual restore, but the deploy that ends the pause cannot pair with it: "
          f"{stale}. {NO_SNAPSHOT_COST[0].upper()}{NO_SNAPSHOT_COST[1:]}.")
    return None


def record(paths: BoxPaths, project: str, snap: PauseSnapshot) -> None:
    """Once the stop succeeded: the deploy that ends this pause pairs with it."""
    if not snap.containers:
        print(f"  {snap.name} stays in backups/ for a manual restore: {snap.service} was "
              f"not running, so whether it runs before the next deploy cannot be told.")
        return
    record_pending(paths, project, snap.name, TAKEN_BY, snap.service, snap.containers)
    print(f"  {snap.name} is the pre-deploy snapshot of the deploy that ends this pause, "
          f"while {snap.service} stays stopped.")
