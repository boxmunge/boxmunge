# SPDX-License-Identifier: Apache-2.0
"""The upgrade apply, per project, under that project's lock.

The lock is taken without waiting, and the checks below are made under it.
Excluded, and reported, rather than touched: a project with a stage left by
0.10.1 (D9: it is left exactly as it is, so a rollback finds 0.10.1's own
state), one with an open install transaction (the core that finishes or
abandons it migrates what it keeps), and one whose lock is held (it keeps
its old configs until its next deploy, resume or recover). Excluded
projects do not fail the upgrade.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import sys

from boxmunge.commands.upgrade_steps import (
    ManifestMigration, Regeneration, _links_into_repository, _migrated, _project_dirs,
    _regenerate_project, exclusion, install_exclusion_text, require_manifest,
)
from boxmunge.fileutil import LockError, project_lock
from boxmunge.git_layout import alert_old_schema, alert_unlinked, relink_advice
from boxmunge.legacy_stage import (
    LegacyStage, alert_legacy, cannot_tell_left_as_is, records_path,
)
from boxmunge.log import log_error, log_warning
from boxmunge.manifest import load_manifest, load_manifest_as_written, write_manifest
from boxmunge.migration import MigrationError
from boxmunge.notify import notify
from boxmunge.release_txn import InstallTxn
from boxmunge.state import StateError

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


@dataclass
class Exclusions:
    """Projects the apply left exactly as they are."""
    legacy: dict[str, str] = field(default_factory=dict)    # name -> legacy kind
    install: dict[str, str] = field(default_factory=dict)   # name -> why
    busy: list[str] = field(default_factory=list)
    # name -> why it cannot be told whether a 0.10.1 stage is on disk
    undetermined: dict[str, str] = field(default_factory=dict)

    def names(self) -> set[str]:
        return set(self.legacy) | set(self.install) | set(self.busy) | set(self.undetermined)


def migrate_one(paths: BoxPaths, project_dir: Path) -> str | None:
    """One project's manifest at the current schema on disk: "written", or
    "in_memory" for a git project, whose link into its repository is never
    written (D19; its operator is alerted to update the repository's file),
    or None if it is already current. Caller holds the project lock."""
    name = project_dir.name
    manifest = load_manifest_as_written(require_manifest(project_dir))
    try:
        migrated = _migrated(project_dir, manifest)
    except MigrationError as e:
        log_error("upgrade", f"{e}. Original manifest left in place.", paths, project=name)
        raise
    if migrated is None:
        return None
    if _links_into_repository(project_dir):
        alert_old_schema(paths, name, manifest.get("schema_version"))
        return "in_memory"
    write_manifest(project_dir / "manifest.yml", migrated)
    return "written"


def _apply_locked(paths: BoxPaths, project_dir: Path, migration: ManifestMigration,
                  regen: Regeneration) -> None:
    name = project_dir.name
    unlinked = alert_unlinked(paths, project_dir,
                              load_manifest_as_written(require_manifest(project_dir)))
    if unlinked:
        migration.unlinked[name] = relink_advice(project_dir, unlinked)
    done = migrate_one(paths, project_dir)
    if done == "written":
        migration.written.append(name)
    elif done == "in_memory":
        migration.in_memory.append(name)
    _regenerate_project(paths, name, load_manifest(project_dir / "manifest.yml"), regen)


def apply_projects(paths: BoxPaths) -> tuple[ManifestMigration, Regeneration, Exclusions]:
    """Migrate and regenerate every project that is not excluded. Raises
    (ManifestError, MigrationError, UpgradeGateError) where the upgrade
    cannot succeed; the shim then rolls back."""
    migration, regen, excluded = ManifestMigration(), Regeneration(), Exclusions()
    for project_dir in _project_dirs(paths):
        name = project_dir.name
        try:
            with project_lock(name, paths):
                why = exclusion(paths, name)
                if why is None:
                    _apply_locked(paths, project_dir, migration, regen)
                elif isinstance(why, LegacyStage):
                    excluded.legacy[name] = why.kind
                elif isinstance(why, OSError):
                    excluded.undetermined[name] = cannot_tell_left_as_is(name, why)
                elif isinstance(why, InstallTxn):
                    excluded.install[name] = install_exclusion_text(paths, name, why)
                else:
                    excluded.install[name] = str(why)
        except LockError:
            excluded.busy.append(name)
            log_warning("upgrade", f"Skipped {name}: held by another operation; it keeps its "
                        f"current configs until its next deploy, resume or recover",
                        paths, project=name)
    for name, why in {**excluded.install, **excluded.undetermined}.items():
        log_warning("upgrade", f"Left {name} as it is (not migrated, regenerated or "
                    f"restarted): {why}", paths, project=name)
    return migration, regen, excluded


def notify_exclusions(paths: BoxPaths, excluded: Exclusions) -> None:
    """A priority-1 alert per legacy project (deduplicated by
    state/legacy-stages.json), and one summary each for open installs and
    busy projects. Sent with no project lock held. A legacy alert whose
    dedupe record cannot be read or written is logged and printed instead:
    the project was still left as is, so it must not fail the upgrade."""
    for name, kind in sorted(excluded.legacy.items()):
        try:
            alert_legacy(paths, name, LegacyStage(kind))
        except (StateError, OSError) as e:
            message = (f"Could not alert that {name} has a release staged by boxmunge 0.10.1 "
                       f"(the dedupe record {records_path(paths)}: {type(e).__name__}: {e}); "
                       f"fix or remove that file. The project was left as is; resolve it with "
                       f"boxmunge-server legacy-stage {name}")
            log_error("upgrade", message, paths, project=name)
            print(f"  WARNING: {message}", file=sys.stderr)
    if excluded.install:
        lines = "\n".join(f"- {n}: {why}" for n, why in sorted(excluded.install.items()))
        _summary(paths, "upgrade: projects with an open install left as they are",
                 f"The upgrade did not migrate, regenerate or restart these projects:\n{lines}",
                 priority=1)
    if excluded.undetermined:
        lines = "\n".join(f"- {n}: {why}" for n, why in sorted(excluded.undetermined.items()))
        _summary(paths, "upgrade: projects that may hold a 0.10.1 stage left as they are",
                 f"The upgrade did not migrate, regenerate or restart these projects:\n"
                 f"{lines}", priority=1)
    if excluded.busy:
        _summary(paths, "upgrade: busy projects skipped",
                 f"These projects were busy and keep their previous configs until their next "
                 f"deploy, resume or recover: {', '.join(sorted(excluded.busy))}")


def _summary(paths: BoxPaths, title: str, body: str, *, priority: int = 0) -> None:
    """notify, but an OSError (an unwritable state or log file on the way) is
    printed and logged instead: the projects were still left as they are."""
    try:
        notify(paths, title, body, component="upgrade", priority=priority)
    except OSError as e:
        message = f"Alert not sent ({title}): {type(e).__name__}: {e}. {body}"
        print(f"  WARNING: {message}", file=sys.stderr)
        log_error("upgrade", message, paths)
