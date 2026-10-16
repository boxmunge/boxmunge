# SPDX-License-Identifier: Apache-2.0
"""The previous release kept by an install transaction (release_txn).

The keep moves today's rollback target aside to ``previous.superseded``
instead of deleting it, so an abandoned install can put everything back;
closing the transaction discards it. previous.json written by the keep is
deterministic (its replaced_at is the transaction's started_at), so a
reader can tell the transaction's own writes from anyone else's.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.release import previous_meta_text

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths
    from boxmunge.release_txn import InstallTxn

SUPERSEDED = "previous.superseded"


def superseded_paths(paths: BoxPaths, project: str) -> tuple[Path, Path]:
    releases = paths.project_releases(project)
    return releases / SUPERSEDED, releases / f"{SUPERSEDED}.json"


def kept_previous_text(txn: InstallTxn) -> str:
    return previous_meta_text(txn.replaced_ref or "", txn.snapshot, txn.started_at, txn.ref)
