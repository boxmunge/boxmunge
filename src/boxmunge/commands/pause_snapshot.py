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
"""
from __future__ import annotations

from dataclasses import dataclass

from boxmunge.backup import BackupKind, resolve_backup_service
from boxmunge.backup_source import backup_source
from boxmunge.commands.backup_cmd import take_snapshot
from boxmunge import docker_containers
from boxmunge.paths import BoxPaths
from boxmunge.pending_snapshot import record_pending

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


def take(paths: BoxPaths, project: str, no_snapshot: bool) -> PauseSnapshot | None:
    """Snapshot the running project. None when there is nothing to take
    (--no-snapshot, backup.type none). Raises PauseRefused, DockerError."""
    if no_snapshot:
        print(f"  No snapshot (--no-snapshot): {NO_SNAPSHOT_COST}.")
        return None
    source = backup_source(paths, project)
    if source.manifest is None:
        raise PauseRefused(f"no snapshot can be taken before the pause: {source.skip}. "
                           f"Nothing was changed. Add --no-snapshot to pause without one "
                           f"({NO_SNAPSHOT_COST})")
    if source.manifest.get("backup", {}).get("type", "none") == "none":
        print("  No snapshot: backup.type is none, so there is no data backup to take.")
        return None
    service = resolve_backup_service(source.manifest)
    running = [c.name for c in docker_containers.project_containers(project)
               if c.service == service and c.running and not c.oneoff]
    print("  Taking a snapshot before pausing...")
    rc, name = take_snapshot(project, paths, BackupKind.PREPAUSE, source.manifest,
                             source.compose_file)
    if rc != 0 or name is None:
        raise PauseRefused(f"the snapshot before the pause was not taken (the backup said "
                           f"why above), so nothing was changed. Fix the backup and pause "
                           f"again, or add --no-snapshot to pause without one "
                           f"({NO_SNAPSHOT_COST})")
    return PauseSnapshot(name, service, running)


def record(paths: BoxPaths, project: str, snap: PauseSnapshot) -> None:
    """Once the stop succeeded: the deploy that ends this pause pairs with it."""
    if not snap.containers:
        print(f"  {snap.name} stays in backups/ for a manual restore: {snap.service} was "
              f"not running, so whether it runs before the next deploy cannot be told.")
        return
    record_pending(paths, project, snap.name, TAKEN_BY, snap.service, snap.containers)
    print(f"  {snap.name} is the pre-deploy snapshot of the deploy that ends this pause, "
          f"while {snap.service} stays stopped.")
