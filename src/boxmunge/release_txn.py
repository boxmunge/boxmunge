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
import sys
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from boxmunge.data_dirs import ReleaseStateError
from boxmunge.fileutil import atomic_write_text, fsync_dir
from boxmunge.release import live_meta_text
from boxmunge.release_keep import discard_superseded, kept_previous_text, superseded_paths
from boxmunge.ulid import generate_ulid

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

TXN_VERSION = 1
SOURCES = ("bundle", "staged", "rollback", "git")
PHASES = ("committed", "previous_kept", "installed", "data_restored", "hook_started",
          "switching")
_KEEP_PHASES = ("committed", "previous_kept", "installed", "hook_started", "switching")
# `--abandon`'s own checkpoints, not steps forward. ABANDONING: it is putting
# the replaced release's code back from previous/ (a rerun does that again;
# previous/ is untouched until CODE_RESTORED). CODE_RESTORED: the code is
# back, and only undoing the keep and closing are left, so a rerun never
# installs from a previous/ the undo has already changed.
ABANDONING = "abandoning"
CODE_RESTORED = "abandoned_code"
ABANDON_PHASES = (ABANDONING, CODE_RESTORED)
# What an earlier attempt this transaction superseded may have done: run its
# pre-deploy hook (data may have changed) or start containers (production
# may run a release whose code is no longer anywhere).
TOUCHED = ("", "hook_started", "switching")
_ROLLBACK_PHASES = ("committed", "installed", "data_restored", "hook_started", "switching")
_FIELDS = ("id", "source", "ref", "replaced_ref", "staged_id", "snapshot", "phase",
           "expect", "previous_before", "had_previous", "touched", "started_at")


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
    previous_before: str | None   # sha of previous.json before the first keep
    had_previous: bool            # previous/ existed before the first keep
    touched: str                  # see TOUCHED: inherited from superseded attempts
    started_at: str

    def reached(self, phase: str) -> bool:
        if self.phase in ABANDON_PHASES:
            return phase == "committed"
        return PHASES.index(self.phase) >= PHASES.index(phase)

    @property
    def abandoning(self) -> bool:
        return self.phase in ABANDON_PHASES

    def data_may_have_changed(self) -> bool:
        """A pre-deploy hook (this one's or a superseded attempt's) may have
        run, or a rollback may have restored data: putting files back alone
        is no longer safe, only a rollback with its snapshot is."""
        return (self.source == "rollback" or self.touched != ""
                or self.reached("hook_started"))

    def containers_may_run_other(self) -> bool:
        """Production may run containers of a release other than the one in
        previous/ (an attempt reached switching)."""
        return self.touched == "switching" or self.reached("switching")

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
    abandoning = txn.phase in ABANDON_PHASES and txn.source != "rollback"
    if (txn.source not in SOURCES or txn.touched not in TOUCHED
            or not (txn.phase in txn.phases() or abandoning)):
        raise ReleaseStateError(f"{path} has source {txn.source!r} at phase "
                                f"{txn.phase!r}. {fix}")
    return txn


def open_txn(paths: BoxPaths, project: str, *, source: str, ref: str,
             replaced_ref: str | None, staged_id: str | None, snapshot: str) -> InstallTxn:
    if os.path.lexists(txn_path(paths, project)):
        raise ReleaseStateError(f"an install transaction is already open for {project}")
    expect = current_expect(paths, project)
    prev = paths.project_releases(project) / "previous"
    return _new(paths, project, source=source, ref=ref, replaced_ref=replaced_ref,
                staged_id=staged_id, snapshot=snapshot, phase="committed",
                previous_before=expect["previous_json_sha256"],
                had_previous=prev.is_dir() and not prev.is_symlink(), touched="")


def _new(paths: BoxPaths, project: str, *, phase: str, **fields: Any) -> InstallTxn:
    if fields["source"] not in SOURCES:
        raise ValueError(f"unknown install source {fields['source']!r}")
    txn = InstallTxn(id=generate_ulid(), phase=phase, expect=current_expect(paths, project),
                     started_at=datetime.now(timezone.utc).isoformat(), **fields)
    _write(paths, project, txn)
    return txn


def supersede_txn(paths: BoxPaths, project: str, old: InstallTxn, *, source: str, ref: str,
                  replaced_ref: str | None, staged_id: str | None, snapshot: str,
                  phase: str) -> InstallTxn:
    """A different deploy takes over ``old`` (fix-forward): one atomic write.

    What the first keep found (previous.json's hash, whether previous/
    existed) is carried over: undoing the keep must restore that, not the
    keep's own copy. So is what ``old`` may have done (``touched``): a fix
    after a failed hook must not become abandonable."""
    on_disk = load_txn(paths, project)
    if on_disk is None or on_disk.id != old.id:
        raise ReleaseStateError(f"the install transaction of {project} changed under the lock")
    if old.abandoning:
        raise ReleaseStateError(f"the install of {old.ref} is being abandoned")
    return _new(paths, project, source=source, ref=ref, replaced_ref=replaced_ref,
                staged_id=staged_id, snapshot=snapshot, phase=phase,
                previous_before=old.previous_before, had_previous=old.had_previous,
                touched=_touched_by(old))


def _touched_by(old: InstallTxn) -> str:
    """What ``old`` and the attempts it superseded may have done. A rollback
    may have restored data, and its containers are of a release that is not
    the one its fix-forward keeps, so it counts as both."""
    if old.source == "rollback" or old.containers_may_run_other():
        return "switching"
    return "hook_started" if old.data_may_have_changed() else ""


def advance(paths: BoxPaths, project: str, txn: InstallTxn, phase: str) -> InstallTxn:
    order = txn.phases()
    if (phase not in order or txn.phase not in order
            or order.index(phase) <= order.index(txn.phase)):
        raise ReleaseStateError(f"install of {txn.ref}: cannot go from {txn.phase} to {phase}")
    new = replace(txn, phase=phase, expect=current_expect(paths, project))
    _write(paths, project, new)
    return new


def mark_abandon(paths: BoxPaths, project: str, txn: InstallTxn, phase: str) -> InstallTxn:
    """Record one of --abandon's checkpoints (see ABANDON_PHASES)."""
    if phase not in ABANDON_PHASES or txn.data_may_have_changed():
        raise ReleaseStateError(f"install of {txn.ref} at {txn.phase} cannot be abandoned")
    new = replace(txn, phase=phase, expect=current_expect(paths, project))
    _write(paths, project, new)
    return new


def close_txn(paths: BoxPaths, project: str, txn: InstallTxn) -> None:
    """The install is over: drop the superseded previous release and the record."""
    discard_superseded(paths, project)
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
    # The keep, and undoing it, move previous.json aside before putting the
    # other one in place; only those two steps run at these phases.
    sup_meta = superseded_paths(paths, project)[1]
    keep_in_progress = (txn.phase in ("committed", *ABANDON_PHASES)
                        and now["previous_json_sha256"] is None
                        and _sha(sup_meta) == txn.previous_before)
    if now["previous_json_sha256"] not in prev_ok and not keep_in_progress:
        problems.append("previous.json was changed by something other than this install")
    return "; ".join(problems) or None


def open_install_reason(paths: BoxPaths, project: str, txn: str | None = None) -> str | None:
    """Why ``project`` must wait for an open install other than ``txn``, or None."""
    try:
        open_txn = load_txn(paths, project)
    except ReleaseStateError as e:
        return str(e)
    if open_txn is None or open_txn.id == txn:
        return None
    return start_refusal(project, open_txn, stale_reason(paths, project, open_txn))


def refuse_if_install_open(paths: BoxPaths, project: str, *, component: str,
                           txn: str | None = None) -> bool:
    """For operator commands that must not run while an install is open:
    print why and return True. Never alerts (compose_guard does, for starts)."""
    from boxmunge.log import log_error
    message = open_install_reason(paths, project, txn)
    if message is None:
        return False
    print(f"ERROR: {project}: {message}.", file=sys.stderr)
    log_error(component, f"Refused: {message}", paths, project=project)
    return True


def rerun_command(project: str, txn: InstallTxn) -> str:
    """The command that resumes ``txn``. A bundle is named: plain
    `prod-deploy` takes the newest bundle, which may be another one."""
    return {"bundle": f"prod-deploy {project} --ref {txn.ref}",
            "staged": f"promote {project}",
            "git": f"prod-deploy {project} --ref {txn.ref}",
            "rollback": f"rollback {project}"}[txn.source]


def abandon_text(project: str, txn: InstallTxn) -> str:
    if txn.replaced_ref is None:
        return (f"'prod-deploy {project} --abandon' removes this first deploy's code "
                f"(containers and data are untouched)")
    return (f"'prod-deploy {project} --abandon' puts {txn.replaced_ref}'s files back "
            f"(containers and data are untouched)")


# Only bundle installs are transactions in this release; promote and git
# deploys join when they are rebuilt on it.
FIX_FORWARD = "or deploy a fix (a different bundle)"


def options_text(project: str, txn: InstallTxn, *, rerun: bool = True) -> str:
    """The operator's ways out of an open install, for its phase. ``rerun``
    False leaves out resuming it (its bundle is gone)."""
    if txn.abandoning:
        return f"rerun 'prod-deploy {project} --abandon' to finish abandoning it"
    lines = [f"rerun '{rerun_command(project, txn)}' to finish it"] if rerun else []
    if not txn.data_may_have_changed():
        lines.append(abandon_text(project, txn))
    if txn.source != "rollback" and txn.data_may_have_changed() and txn.replaced_ref:
        lines.append(f"'rollback {project}' restores {txn.snapshot or 'no data snapshot'} "
                     f"with {txn.replaced_ref}")
    lines.append(FIX_FORWARD)
    return "; ".join(lines)


def start_refusal(project: str, txn: InstallTxn, stale: str | None) -> str:
    if stale:
        return (f"an install of {txn.ref} ({txn.source}, phase {txn.phase}) is recorded "
                f"in .releases/install.json, but {stale}. Check that production is what "
                f"live.json says, then run 'boxmunge-server install-txn {project} --drop'")
    return (f"an install of {txn.ref} ({txn.source}) is open at phase {txn.phase}: "
            f"{options_text(project, txn)}")
