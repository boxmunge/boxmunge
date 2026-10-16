# SPDX-License-Identifier: Apache-2.0
"""Which manifest a backup reads: the one of the release the containers run.

Without an open install that is the project dir's. During one (see
release_txn), the project dir may already hold the new release's files
while the old containers still run: from previous_kept to hook_started the
running release is the kept one; at switching (only after a crash) it is
ambiguous, and while a rollback is open the data is being restored, so
both skip. A manifest or install record that cannot be read is an error
(ManifestError, ReleaseStateError), never a skip.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from boxmunge.manifest import load_manifest
from boxmunge.release import previous_dir
from boxmunge.release_txn import load_txn

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


@dataclass(frozen=True)
class BackupSource:
    manifest: dict[str, Any] | None   # None: skip the backup
    skip: str = ""
    alert: bool = False


def backup_source(paths: BoxPaths, project: str) -> BackupSource:
    """Raises ManifestError or ReleaseStateError when it cannot tell."""
    txn = load_txn(paths, project)
    if txn is None or txn.phase == "committed" and txn.source != "rollback":
        return BackupSource(load_manifest(paths.project_manifest(project)))
    if txn.source == "rollback":
        return BackupSource(None, skip=f"a rollback to {txn.ref} is restoring its data")
    if txn.phase == "switching":
        return BackupSource(None, alert=True, skip=(
            f"an install of {txn.ref} was interrupted at switching, so which release "
            f"the containers run is ambiguous; finish it ('{txn.source}' rerun) first"))
    if txn.replaced_ref is None:
        return BackupSource(None, skip=f"the first deploy ({txn.ref}) is not running yet")
    return BackupSource(load_manifest(previous_dir(paths, project) / "manifest.yml"))
