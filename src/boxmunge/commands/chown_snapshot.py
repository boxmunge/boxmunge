# SPDX-License-Identifier: Apache-2.0
"""data chown's snapshot: the project's backup, before ownership changes.

While the backup service runs, the project's own backup is taken as usual
(its dump runs in the service). When it is stopped (the project is
quarantined, paused or stopped by the health monitor, or the service was
stopped for another reason), its data is at rest, and the dump runs in a
one-off container of it, offline (backup_offline), so the change keeps a
data rollback. A dump that needs the service running cannot be taken that
way: the refusal names the state's own way out first, and `--no-snapshot`
only last, saying what it gives up.
"""
from __future__ import annotations

from pathlib import Path

from boxmunge.backup import BackupKind, resolve_backup_service
from boxmunge.backup_source import backup_source
from boxmunge.commands.backup_cmd import take_snapshot
from boxmunge.commands.deploy_checks import service_mounts
from boxmunge.commands.health_state import is_monitor_stopped
from boxmunge.docker_containers import running_by_service
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.pause import awaiting_deploy
from boxmunge.paths import BoxPaths
from boxmunge.redeploy_hint import redeploy_command
from boxmunge.pending_snapshot import age, pending_for_live
from boxmunge.release_txn import open_install_reason

NO_SNAPSHOT_COST = "a rollback of the next deploy then cannot restore data"


class SnapshotRefused(Exception):
    """No snapshot could be taken; nothing was changed. Says why and what to do."""


def _rw_sharer(services: dict, service: str, mounts: list) -> str | None:
    """Another service that mounts `service`'s data (`mounts`) read-write,
    and so can change it while `service` is stopped; None when none does."""
    def overlaps(own, m) -> bool:
        if own.kind == "volume":
            return own.source == m.source
        a, b = Path(str(own.source)), Path(str(m.source))
        return a == b or a in b.parents or b in a.parents
    for other, svc in sorted(services.items()):
        for m in service_mounts(svc) if other != service else ():
            if m.read_only or m.kind not in ("bind", "volume"):
                continue
            hit = next((own for own in mounts if own.kind == m.kind and overlaps(own, m)), None)
            if hit is not None:
                return f"{other} also mounts {hit.source} read-write"
    return None


def _why_stopped(paths: BoxPaths, project: str, backup_service: str) -> tuple[str, str]:
    """(why the backup service is not running, the state's own way out). An
    open install comes first: it refuses every start, the one-off dump's
    included, until its own ways out."""
    install = open_install_reason(paths, project)
    if install is not None:
        return (install,
                "take one of that install's ways out first (abandoning it leaves the "
                "containers and data as they are), then run data chown again")
    block = is_blocked(project, paths)
    if block is not None and block.reason is BlockReason.QUARANTINED:
        return ("the project is CVE-quarantined",
                f"run `boxmunge security resume {project}` once its images are clean (that "
                f"starts it, and the backup dumps from the running service), then run "
                f"data chown again")
    if block is not None and block.reason is BlockReason.PAUSED and \
            awaiting_deploy(project, paths):
        return ("the project is paused, awaiting a deploy (resume --no-start)",
                f"deploy it (`{redeploy_command(paths, project)}`; the pause ends once it "
                f"starts), then run data chown again")
    if block is not None and block.reason is BlockReason.PAUSED:
        return ("the project is paused",
                f"run `boxmunge resume {project}`, then run data chown again")
    if is_monitor_stopped(project, paths):
        return ("the health monitor stopped the project",
                f"fix the cause and run `boxmunge recover {project}`, then run data chown "
                f"again")
    return (f"{backup_service} is stopped",
            f"start {backup_service} (`{redeploy_command(paths, project)}` does), then run "
            f"data chown again")


def _take(paths: BoxPaths, project: str, manifest: dict, compose_file: Path | None,
          backup_service: str) -> tuple[str, bool]:
    """Take the snapshot: its name, and whether the backup service was
    stopped (the dump ran offline). Raises SnapshotRefused."""
    if backup_service in running_by_service(project):
        print("  Taking a snapshot before changing ownership...")
        rc, name = take_snapshot(project, paths, BackupKind.PRECHOWN, manifest, compose_file)
        if rc == 0 and name is not None:
            return name, False
        raise SnapshotRefused(
            f"the snapshot before the ownership change was not taken (the backup said "
            f"why above), so nothing was changed. Fix the backup and run data chown "
            f"again, or add --no-snapshot to change ownership without one "
            f"({NO_SNAPSHOT_COST})")
    why, way_out = _why_stopped(paths, project, backup_service)
    print(f"  The backup service {backup_service} is not running ({why}): taking the "
          f"snapshot from its data at rest, in a one-off container of its image run "
          f"offline (no network, no ports, none of its hooks) only for the dump...")
    rc, name = take_snapshot(project, paths, BackupKind.PRECHOWN, manifest, compose_file,
                             offline=True)
    if rc == 0 and name is not None:
        return name, True
    raise SnapshotRefused(
        f"no snapshot could be taken before the ownership change: {why}, and the dump "
        f"could not run over its stopped data (the backup said why above; a dump that "
        f"needs its service running, such as pg_dump, cannot). Nothing was changed. To "
        f"keep a snapshot, {way_out}. Only if you cannot, add --no-snapshot to change "
        f"ownership without one ({NO_SNAPSHOT_COST})")


def snapshot_first(paths: BoxPaths, project: str, service: str, services: dict,
                   mounts: list, no_snapshot: bool) -> str | None:
    """Take the project's snapshot before `service` is stopped; a failed one
    refuses the chown (SnapshotRefused). Returns its name when the next
    deploy is to use it: `service` is the backup service (stopping it leaves
    that deploy's dump nothing to run in) and no other service can write its
    data meanwhile. The caller records it once the stop succeeded."""
    taken = pending_for_live(paths, project)
    if taken is not None:
        print(f"  The snapshot {taken['name']}, taken by {taken['taken_by']} {age(taken)} "
              f"ago, stays the next deploy's pre-deploy snapshot: {taken['service']} has "
              f"not run since. No new one is taken.")
        return None
    if no_snapshot:
        print(f"  No snapshot (--no-snapshot): {NO_SNAPSHOT_COST}.")
        return None
    # The running release's manifest: during an open install the project
    # dir may already hold the new one's.
    source = backup_source(paths, project)
    if source.manifest is None:
        raise SnapshotRefused(
            f"no snapshot can be taken before the ownership change: {source.skip}. "
            f"Nothing was changed. Add --no-snapshot to change ownership without one "
            f"({NO_SNAPSHOT_COST})")
    if source.manifest.get("backup", {}).get("type", "none") == "none":
        print("  No snapshot: backup.type is none, so there is no data backup to take.")
        return None
    backup_service = resolve_backup_service(source.manifest)
    name, offline = _take(paths, project, source.manifest, source.compose_file, backup_service)
    sharer = _rw_sharer(services, service, mounts) if service == backup_service else None
    if service == backup_service and sharer is None:
        return name
    why = (f"{sharer}, so the data can change after the snapshot while {service} is "
           f"stopped; the next deploy dumps afresh if it can (it warns if it cannot)"
           if sharer else
           f"the backup service {backup_service} is another service, stopped too, whose "
           f"data can change if it runs before the deploy; the next deploy dumps from it "
           f"if it runs by then (it warns if it cannot)"
           if offline else
           f"the backup service {backup_service} keeps running, so the next deploy takes "
           f"its own pre-deploy snapshot")
    print(f"  {name} stays in backups/ for a manual restore, not for the next deploy: {why}.")
    return None
