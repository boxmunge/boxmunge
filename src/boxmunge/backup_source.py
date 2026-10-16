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
from boxmunge.release_txn import CODE_RESTORED, load_txn, options_text

if TYPE_CHECKING:
    from pathlib import Path

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
