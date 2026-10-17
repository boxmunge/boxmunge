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

from boxmunge.commands.upgrade_steps import (
    ManifestMigration, Regeneration, _links_into_repository, _migrated, _project_dirs,
    _regenerate_project,
)
from boxmunge.fileutil import LockError, project_lock
from boxmunge.git_layout import alert_old_schema, alert_unlinked, relink_advice
from boxmunge.legacy_stage import LegacyStage, alert_legacy, legacy_stage
from boxmunge.log import log_error, log_warning
from boxmunge.manifest import load_manifest, load_manifest_as_written, write_manifest
from boxmunge.migration import MigrationError
from boxmunge.notify import notify
from boxmunge.release_txn import open_install_reason

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


@dataclass
class Exclusions:
    """Projects the apply left exactly as they are."""
    legacy: dict[str, str] = field(default_factory=dict)    # name -> legacy kind
    install: dict[str, str] = field(default_factory=dict)   # name -> why
    busy: list[str] = field(default_factory=list)

    def names(self) -> set[str]:
        return set(self.legacy) | set(self.install) | set(self.busy)


def exclusion(paths: BoxPaths, name: str) -> tuple[str, str] | None:
    """("legacy", kind) or ("install", why) for a project the apply must
    leave alone, or None. Read-only."""
    stage = legacy_stage(paths, name)
    if stage is not None:
        return "legacy", stage.kind
    why = open_install_reason(paths, name)
    if why is not None:
        return "install", why
    return None


def migrate_one(paths: BoxPaths, project_dir: Path) -> str | None:
    """One project's manifest at the current schema on disk: "written", or
    "in_memory" for a git project, whose link into its repository is never
    written (D19; its operator is alerted to update the repository's file),
    or None if it is already current. Caller holds the project lock."""
    name = project_dir.name
    manifest = load_manifest_as_written(project_dir / "manifest.yml")
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
                              load_manifest_as_written(project_dir / "manifest.yml"))
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
                elif why[0] == "legacy":
                    excluded.legacy[name] = why[1]
                else:
                    excluded.install[name] = why[1]
        except LockError:
            excluded.busy.append(name)
            log_warning("upgrade", f"Skipped {name}: held by another operation; it keeps its "
                        f"current configs until its next deploy, resume or recover",
                        paths, project=name)
    for name, why in excluded.install.items():
        log_warning("upgrade", f"Left {name} as it is (not migrated, regenerated or "
                    f"restarted): {why}", paths, project=name)
    return migration, regen, excluded


def notify_exclusions(paths: BoxPaths, excluded: Exclusions) -> None:
    """A priority-1 alert per legacy project (deduplicated by
    state/legacy-stages.json), and one summary each for open installs and
    busy projects. Sent with no project lock held."""
    for name, kind in sorted(excluded.legacy.items()):
        alert_legacy(paths, name, LegacyStage(kind))
    if excluded.install:
        lines = "\n".join(f"- {n}: {why}" for n, why in sorted(excluded.install.items()))
        notify(paths, "upgrade: projects with an open install left as they are",
               f"The upgrade did not migrate, regenerate or restart these projects:\n{lines}",
               component="upgrade", priority=1)
    if excluded.busy:
        notify(paths, "upgrade: busy projects skipped",
               f"These projects were busy and keep their previous configs until their next "
               f"deploy, resume or recover: {', '.join(sorted(excluded.busy))}",
               component="upgrade")
