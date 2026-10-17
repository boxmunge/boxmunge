# SPDX-License-Identifier: Apache-2.0
"""Which manifest a backup reads: the one of the release the containers run.

Without an open install that is the project dir's. During one (see
release_txn), the project dir may already hold the new release's files
while the old containers still run: from previous_kept to hook_started the
running release is the kept one; at switching (only after a crash) it is
ambiguous, and while a rollback is open the data is being restored, so
both skip. A manifest or install record that cannot be read is an error
(ManifestError, ReleaseStateError), never a skip.

A stage left by boxmunge 0.10.1 comes first: its evidence says which
release the containers run. Only evidence that cannot be read (Docker,
the reflog, the prestage, a ref) skips, with an alert naming the cause; a
never-deployed git project skips without one (it has no data).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from boxmunge.git_slot import GitRefError, resolve_recorded_ref, show_manifest
from boxmunge.legacy_stage import (
    EvidenceError, LegacyStage, cannot_tell, evidence, legacy_stage, real_dir_problem,
)
from boxmunge.manifest import ManifestError, at_current_schema, load_manifest
from boxmunge.release import previous_dir
from boxmunge.release_txn import CODE_RESTORED, load_txn, options_text

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


@dataclass(frozen=True)
class BackupSource:
    manifest: dict[str, Any] | None   # None: skip the backup
    skip: str = ""
    alert: bool = False
    # The running release's compose file when it is not the project dir's.
    compose_file: Path | None = None


def backup_source(paths: BoxPaths, project: str) -> BackupSource:
    """Raises ManifestError or ReleaseStateError when it cannot tell."""
    try:
        stage = legacy_stage(paths, project)
    except OSError as e:
        return BackupSource(None, alert=True, skip=cannot_tell(project, e))
    if stage is not None:
        return _legacy(paths, project, stage)
    txn = load_txn(paths, project)
    if txn is None or txn.source != "rollback" and txn.phase in ("committed", CODE_RESTORED):
        return BackupSource(load_manifest(paths.project_manifest(project)))
    if txn.source == "rollback":
        return BackupSource(None, skip=f"a rollback to {txn.ref} is restoring its data")
    if txn.containers_may_run_other():
        return BackupSource(None, alert=True, skip=(
            f"an install of {txn.ref} (at {txn.phase}, or one it replaced) may have started its "
            f"containers, so which release production runs is ambiguous; finish it "
            f"first: {options_text(project, txn)}"))
    if txn.replaced_ref is None:
        return BackupSource(None, skip=f"the first deploy ({txn.ref}) is not running yet")
    kept = previous_dir(paths, project)
    return BackupSource(load_manifest(kept / "manifest.yml"),
                        compose_file=kept / "compose.yml")


def _legacy(paths: BoxPaths, project: str, stage: LegacyStage) -> BackupSource:
    """The manifest matching the containers a 0.10.1 stage left running."""
    pdir = paths.project_dir(project)
    if stage.kind == "leftover":
        # A promote whose unstage failed: production runs the promoted release.
        return BackupSource(load_manifest(pdir / "manifest.yml"))
    try:
        ev = evidence(paths, project, stage)
        running = (_running_commit(pdir / "repo", ev.current_ref)
                   if stage.kind == "git" and ev.classification == "untouched"
                   and ev.current_ref is not None else None)
        kept = pdir / ".releases" / "prestage" / "release"
        problem = (real_dir_problem(kept)
                   if stage.kind == "bundle" and ev.classification == "untouched" else None)
        if problem:
            raise EvidenceError(problem)
    except EvidenceError as e:
        return BackupSource(None, alert=True, skip=(
            f"a release staged by boxmunge 0.10.1 is in place and which release production "
            f"runs cannot be told: {e}"))
    if ev.classification == "recreated":
        # Production was started from the staged files in the project dir.
        return BackupSource(load_manifest(pdir / "manifest.yml"))
    if stage.kind == "git" and ev.classification == "untouched" and ev.current_ref is None:
        return BackupSource(None, skip=(
            "it was never deployed (a 0.10.1 stage of its clone): production has no data"))
    if running is not None:
        # The dump still execs through the project dir's compose.yml, which
        # follows repo/'s staged checkout: if the staged release renamed the
        # backup service, the dump fails (noisily) rather than reaching the
        # wrong container. Resolving the stage is the fix, not a rewrite here.
        return BackupSource(_from_git(pdir / "repo", running))
    return BackupSource(load_manifest(kept / "manifest.yml"), compose_file=kept / "compose.yml")


def _running_commit(repo: Path, current_ref: str | None) -> str:
    try:
        return resolve_recorded_ref(repo, current_ref or "")
    except GitRefError as e:
        raise EvidenceError(f"cannot resolve the deployed commit: {e}") from e


def _from_git(repo: Path, sha: str) -> dict[str, Any]:
    """manifest.yml as committed at `sha`, loaded in memory at the current
    schema. Raises ManifestError when it cannot be read."""
    where = Path(f"{repo}@{sha}:manifest.yml")
    try:
        doc = yaml.safe_load(show_manifest(repo, sha))
    except GitRefError as e:
        raise ManifestError(f"Cannot read manifest {where}: {e}") from e
    except yaml.YAMLError as e:
        raise ManifestError(f"Manifest is not valid YAML: {where}: {e}") from e
    if not isinstance(doc, dict):
        raise ManifestError(f"Manifest is not a YAML mapping: {where}")
    return at_current_schema(doc, where)
