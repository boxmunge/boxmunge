# SPDX-License-Identifier: Apache-2.0
"""The install transaction: ``.releases/install.json``.

Every production install (bundle deploy, promote, git deploy, rollback)
runs inside one. The record names the release being installed, the one it
replaces, the snapshot that pairs with the replaced release, and the phase
reached. While it is open, compose_guard refuses every production start
except the core resuming it. ``expect`` holds the SHA-256 of live.json and
previous.json as this transaction last left them: a mismatch that none of
the transaction's own steps explains means something outside it changed
production (an older release after a platform rollback, a hand edit), and
nothing is resumed, abandoned or dropped automatically.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from boxmunge.data_dirs import ReleaseStateError
from boxmunge.fileutil import atomic_write_text, discard_dir, fsync_dir
from boxmunge.release import live_meta_text
from boxmunge.release_keep import kept_previous_text, superseded_paths
from boxmunge.ulid import generate_ulid

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

TXN_VERSION = 1
SOURCES = ("bundle", "staged", "rollback", "git")
PHASES = ("committed", "previous_kept", "installed", "data_restored", "hook_started",
          "switching")
_KEEP_PHASES = ("committed", "previous_kept", "installed", "hook_started", "switching")
_ROLLBACK_PHASES = ("committed", "installed", "data_restored", "hook_started", "switching")
_FIELDS = ("id", "source", "ref", "replaced_ref", "staged_id", "snapshot", "phase",
           "expect", "previous_before", "started_at")


@dataclass(frozen=True)
class InstallTxn:
    id: str
    source: str
    ref: str
    replaced_ref: str | None
    staged_id: str | None
    snapshot: str
    phase: str
    expect: dict[str, str | None]
    previous_before: str | None
    started_at: str

    def reached(self, phase: str) -> bool:
        return PHASES.index(self.phase) >= PHASES.index(phase)

    def phases(self) -> tuple[str, ...]:
        return _ROLLBACK_PHASES if self.source == "rollback" else _KEEP_PHASES


def txn_path(paths: BoxPaths, project: str) -> Path:
    return paths.project_releases(project) / "install.json"


def _sha(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        return None


def _text_sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def current_expect(paths: BoxPaths, project: str) -> dict[str, str | None]:
    releases = paths.project_releases(project)
    return {"live_json_sha256": _sha(releases / "live.json"),
            "previous_json_sha256": _sha(releases / "previous.json")}


def _write(paths: BoxPaths, project: str, txn: InstallTxn) -> None:
    doc = {"version": TXN_VERSION, **asdict(txn)}
    atomic_write_text(txn_path(paths, project), json.dumps(doc, indent=2) + "\n", mode=0o644)


def load_txn(paths: BoxPaths, project: str) -> InstallTxn | None:
    """The open transaction, or None. Raises ReleaseStateError, naming the
    file, for anything this release did not write."""
    path = txn_path(paths, project)
    if not os.path.lexists(path):
        return None
    fix = f"Inspect it; `boxmunge-server install-txn {project} --drop` removes it."
    try:
        doc = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ReleaseStateError(f"Cannot read {path}: {e}. {fix}") from e
    if not isinstance(doc, dict) or doc.get("version") != TXN_VERSION:
        raise ReleaseStateError(f"{path} is not a version-{TXN_VERSION} install.json. {fix}")
    try:
        txn = InstallTxn(**{k: doc[k] for k in _FIELDS})
    except KeyError as e:
        raise ReleaseStateError(f"{path} is missing {e}. {fix}") from e
    if txn.source not in SOURCES or txn.phase not in txn.phases():
        raise ReleaseStateError(f"{path} has source {txn.source!r} at phase "
                                f"{txn.phase!r}. {fix}")
    return txn


def open_txn(paths: BoxPaths, project: str, *, source: str, ref: str,
             replaced_ref: str | None, staged_id: str | None, snapshot: str) -> InstallTxn:
    if os.path.lexists(txn_path(paths, project)):
        raise ReleaseStateError(f"an install transaction is already open for {project}")
    return _new(paths, project, source=source, ref=ref, replaced_ref=replaced_ref,
                staged_id=staged_id, snapshot=snapshot, phase="committed")


def _new(paths: BoxPaths, project: str, *, phase: str, **fields: Any) -> InstallTxn:
    if fields["source"] not in SOURCES:
        raise ValueError(f"unknown install source {fields['source']!r}")
    expect = current_expect(paths, project)
    txn = InstallTxn(id=generate_ulid(), phase=phase, expect=expect,
                     previous_before=expect["previous_json_sha256"],
                     started_at=datetime.now(timezone.utc).isoformat(), **fields)
    _write(paths, project, txn)
    return txn


def supersede_txn(paths: BoxPaths, project: str, old: InstallTxn, *, source: str, ref: str,
                  replaced_ref: str | None, staged_id: str | None, snapshot: str,
                  phase: str) -> InstallTxn:
    """A different deploy takes over ``old`` (fix-forward): one atomic write."""
    on_disk = load_txn(paths, project)
    if on_disk is None or on_disk.id != old.id:
        raise ReleaseStateError(f"the install transaction of {project} changed under the lock")
    return _new(paths, project, source=source, ref=ref, replaced_ref=replaced_ref,
                staged_id=staged_id, snapshot=snapshot, phase=phase)


def advance(paths: BoxPaths, project: str, txn: InstallTxn, phase: str) -> InstallTxn:
    order = txn.phases()
    if phase not in order or order.index(phase) <= order.index(txn.phase):
        raise ReleaseStateError(f"install of {txn.ref}: cannot go from {txn.phase} to {phase}")
    new = replace(txn, phase=phase, expect=current_expect(paths, project))
    _write(paths, project, new)
    return new


def close_txn(paths: BoxPaths, project: str, txn: InstallTxn) -> None:
    """The install is over: drop the superseded previous release and the record."""
    sup_dir, sup_meta = superseded_paths(paths, project)
    discard_dir(sup_dir)
    if os.path.lexists(sup_meta):
        sup_meta.unlink()
    path = txn_path(paths, project)
    if os.path.lexists(path):
        path.unlink()
    fsync_dir(path.parent)


def stale_reason(paths: BoxPaths, project: str, txn: InstallTxn) -> str | None:
    """Why the files on disk are not as this transaction left them, or None.

    Accepted: ``expect``, or what this transaction's own steps write (the
    keep's previous.json, live.json naming ``ref`` or ``replaced_ref``), so a
    crash between a step and its phase write is never called stale.
    """
    now = current_expect(paths, project)
    live_ok = {txn.expect["live_json_sha256"], _text_sha(live_meta_text(txn.ref)),
               _text_sha(live_meta_text(txn.replaced_ref)) if txn.replaced_ref else None}
    prev_ok = {txn.expect["previous_json_sha256"], txn.previous_before,
               _text_sha(kept_previous_text(txn))}
    if txn.source == "rollback":
        prev_ok.add(None)  # a successful rollback discards its target before closing
    problems = []
    if now["live_json_sha256"] not in live_ok:
        problems.append(f"live.json no longer names {txn.ref} or {txn.replaced_ref}")
    sup_meta = superseded_paths(paths, project)[1]
    keep_in_progress = (now["previous_json_sha256"] is None
                        and _sha(sup_meta) == txn.previous_before)
    if now["previous_json_sha256"] not in prev_ok and not keep_in_progress:
        problems.append("previous.json was changed by something other than this install")
    return "; ".join(problems) or None


def rerun_command(project: str, txn: InstallTxn) -> str:
    return {"bundle": f"prod-deploy {project}", "staged": f"promote {project}",
            "git": f"prod-deploy {project} --ref {txn.ref}",
            "rollback": f"rollback {project}"}[txn.source]


def options_text(project: str, txn: InstallTxn) -> str:
    """The operator's ways out of an open install, for its phase."""
    replaced = txn.replaced_ref or "the empty project"
    lines = [f"rerun '{rerun_command(project, txn)}' to finish it"]
    if txn.source != "rollback" and not txn.reached("hook_started"):
        lines.append(f"'prod-deploy {project} --abandon' puts {replaced}'s files back "
                     f"(containers and data are untouched)")
    if txn.source != "rollback" and txn.reached("hook_started"):
        lines.append(f"'rollback {project}' restores {txn.snapshot or 'no snapshot'} "
                     f"with {replaced}")
    lines.append("or deploy a fix (a different bundle, SHA or staged release)")
    return "; ".join(lines)


def start_refusal(project: str, txn: InstallTxn, stale: str | None) -> str:
    if stale:
        return (f"an install of {txn.ref} ({txn.source}, phase {txn.phase}) is recorded "
                f"in .releases/install.json, but {stale}. Check that production is what "
                f"live.json says, then run 'boxmunge-server install-txn {project} --drop'")
    return (f"an install of {txn.ref} ({txn.source}) is open at phase {txn.phase}: "
            f"{options_text(project, txn)}")
