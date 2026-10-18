# SPDX-License-Identifier: Apache-2.0
"""Phase 0: every refusal, each listing every offender, and the report.

`userns-migrate --check` stops here and changes nothing; `userns-migrate`
and `userns-rollback` run it again once they hold the locks, because deploys
may have changed the box since. A rollback runs the inverse checks: no
probation, image or namespace refusals (the remapped daemon already runs
everything it holds), the inverse shift scan.
"""
from __future__ import annotations

import os
from pathlib import Path

from boxmunge.bind_sources import BindSourceError, read_record
from boxmunge.compose_resolve import ComposeResolveError, resolve_deployed_config
from boxmunge.compose_version import compose_version_problem
from boxmunge.config import ConfigError, load_config
from boxmunge.cve.quarantine import is_quarantined, quarantine_action_complete
from boxmunge.legacy_stage import legacy_stage_refusal
from boxmunge.manifest import ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.pause import is_paused, pause_incomplete
from boxmunge.release_txn import open_install_reason
from boxmunge.run_as import unmappable_users
from boxmunge.staged_release import has_slot, slot_debris
from boxmunge.state import StateError, read_state
from boxmunge.userns import offset as userns_offset
from boxmunge.userns import preflight_checks as checks
from boxmunge.userns.daemon_config import DaemonConfigError, merged_daemon_json
from boxmunge.userns.inventory import Inventory
from boxmunge.userns.journal import FORWARD
from boxmunge.userns.preflight_checks import Report
from boxmunge.userns.shift import Direction

__all__ = ["PreflightRefused", "Report", "preflight"]


class PreflightRefused(Exception):
    def __init__(self, report: Report) -> None:
        self.report = report
        super().__init__(report.text())


def _daemon_json(r: Report) -> None:
    path = userns_offset.ETC / "docker" / "daemon.json"
    try:
        merged_daemon_json(path.read_bytes() if path.exists() else None)
    except DaemonConfigError as e:
        r.refusals.append(f"{path}: {e}")


def _project_state(paths: BoxPaths, p: str, r: Report) -> None:
    for reason in (open_install_reason(paths, p), legacy_stage_refusal(paths, p)):
        if reason:
            r.refusals.append(reason)
    if has_slot(paths, p) or slot_debris(paths, p):
        r.refusals.append(f"{p}: a release is staged (or a stage left debris); promote or "
                          f"unstage it first: the migration carries production only")
    if is_quarantined(p, paths) and not quarantine_action_complete(p, paths):
        r.refusals.append(f"{p}: a quarantine is half-applied; finish it before migrating")
    if pause_incomplete(p, paths):
        r.refusals.append(f"{p}: a pause is half-applied; finish it with pause or resume")


def _lifecycle(paths: BoxPaths, inv: Inventory, r: Report, *, forward: bool) -> None:
    if forward and paths.probation.exists():
        r.refusals.append("an upgrade probation is open; migrate after it ends")
    try:
        if forward and not load_config(paths).get("backup_remote"):
            r.refusals.append("backup_remote is not configured; the migration syncs a fresh "
                              "backup of every project off-site before any downtime")
    except ConfigError as e:
        r.refusals.append(str(e))
    for p in inv.projects:
        _project_state(paths, p, r)


def _compose_users(paths: BoxPaths, inv: Inventory, r: Report) -> None:
    """Compose `user:` ids a remapped daemon cannot map."""
    for p in inv.projects:
        if not paths.project_manifest(p).exists():
            continue
        files = ["compose.yml"] + (["compose.boxmunge.yml"]
                                   if paths.project_compose_override(p).exists() else [])
        try:
            model = resolve_deployed_config(paths.project_dir(p), files, p, all_profiles=True)
        except (ComposeResolveError, OSError) as e:
            r.refusals.append(f"{p}: cannot read its compose model: {e}")
            continue
        r.refusals += [f"{p}: {problem}" for problem in unmappable_users(model["services"])]


def _undeclared_root(paths: BoxPaths, r: Report) -> None:
    """Registry services that run as their image's root and whose project's
    users were never decided: the next deploy refuses them until declared,
    so the migration refuses them now, with the line to add."""
    from boxmunge.health_checks.service_users import GUIDE, pending_declarations
    pending, problems = pending_declarations(paths)
    r.refusals += [f"cannot tell who a service runs as: {p}" for p in problems]
    for entry in pending:
        project_service = entry.split(" ", 1)[0]
        service = project_service.split("/", 1)[1]
        r.refusals.append(
            f"{entry} runs as its image's root and its user was never decided. Declare it in "
            f"the manifest, under services.{service}: security: {{user: image, reason: "
            f"\"<why>\"}} (or a \"<uid>:<gid>\"), deploy, then migrate ({GUIDE})")


def _records(paths: BoxPaths, inv: Inventory, r: Report) -> None:
    """The binds record against what containers really mount: reported only."""
    for p in inv.projects:
        prefix = str(paths.project_dir(p)) + "/"
        mounted = {m.source[len(prefix):] for c in inv.containers if c.compose_project == p
                   for m in c.mounts
                   if m.kind in ("data", "readable") and m.source.startswith(prefix)}
        try:
            recorded = set(read_record(paths.project_bind_record(p))["sources"])
        except BindSourceError:
            r.notes.append(f"{p}: no binds record (deployed before the start checks); its "
                           f"mounts come from its containers: {sorted(mounted) or 'none'}")
            continue
        for rel in sorted(recorded - mounted):
            r.notes.append(f"{p}: {rel} is in the binds record but no container mounts it")
        for rel in sorted(mounted - recorded):
            r.notes.append(f"{p}: {rel} is mounted but not in the binds record")


def _unmounted_data(paths: BoxPaths, inv: Inventory, r: Report) -> None:
    """data/ entries no container mounts (a removed service's) are not shifted."""
    carried = set(inv.data_binds())
    for p in inv.projects:
        data = paths.project_data(p)
        if not data.is_dir() or data.is_symlink():
            continue
        for entry in sorted(os.listdir(data)):
            path = str(data / entry)
            if not any(c == path or c.startswith(path + "/") or path.startswith(c + "/")
                       for c in carried):
                r.notes.append(f"{path} is not mounted by any container, so it is not "
                               f"shifted; if a service mounts it again, give it to that "
                               f"service's user with boxmunge data chown")


def _notes(paths: BoxPaths, inv: Inventory, r: Report) -> None:
    r.notes.append(f"prior store: {inv.driver} ({inv.driver_type or 'graph driver'}) at {inv.root}")
    for p in inv.projects:
        try:
            status = read_state(paths.project_health_state(p)).get("status")
        except StateError as e:
            status = f"unknown ({e})"
        if status not in (None, "ok", "healthy"):
            r.notes.append(f"{p} is currently {status}")
        if is_paused(p, paths):
            r.notes.append(f"{p} is paused: it gets no pre-migration backup (its containers are "
                           f"stopped); its data is carried like any other")
    _records(paths, inv, r)
    _unmounted_data(paths, inv, r)
    if any(m.source == str(paths.caddyfile) for c in inv.containers for m in c.mounts):
        r.notes.append(f"{paths.caddyfile} is made 0644: Caddy's remapped root reads it "
                       f"through the other bits (userns-rollback puts its mode back)")
    carried = sum(i.size for i in inv.images if i.carried)
    estimate = carried / 100e6 + r.files / 20000 + 2 * 15 + 30 * len(inv.projects)
    r.notes.append(f"estimated downtime: about {int(estimate)} s ({carried // 10**6} MB of images, "
                   f"{r.files} files to shift, two daemon restarts, {len(inv.projects)} project "
                   f"starts and smokes)")


def preflight(paths: BoxPaths, inv: Inventory, *, direction: str, offset: int,
              images_dir: Path, scan_images: bool = True,
              extra_binds: list[str] | None = None) -> Report:
    """`extra_binds`: bind data a rollback also unshifts (the forward
    inventory's, which the remapped daemon may no longer mount)."""
    r = Report()
    forward = direction == FORWARD
    checks.docker_version(inv, r)
    problem = compose_version_problem()
    if problem:
        r.refusals.append(problem)
    _lifecycle(paths, inv, r, forward=forward)
    checks.containers(inv, r)
    checks.volumes(inv, r, forward=forward)
    checks.registries(inv, r)
    checks.data(inv, offset, Direction.FORWARD if forward else Direction.INVERSE, r,
                extra_binds or [])
    if forward:
        checks.prior_store(inv, r)
        _daemon_json(r)
        checks.namespaces(inv, r)
        checks.readability(paths, inv, r)
        checks.filesystem(inv, r)
        try:
            _compose_users(paths, inv, r)
        except ManifestError as e:
            r.refusals.append(str(e))
        _undeclared_root(paths, r)
        if scan_images:
            checks.images(inv, r)
    checks.disk(inv, r, images_dir)
    _notes(paths, inv, r)
    return r
