# SPDX-License-Identifier: Apache-2.0
"""A git deploy inside an install transaction (release_txn): source "git",
or "staged" for the promote of a git slot.

The ref was resolved to a full SHA before this core runs, and is never
resolved again: a resume checks out the same commit. The data snapshot is
taken with the live manifest before anything is checked out; then the SHA
is checked out detached in repo/ (there is no `git pull`). Git keeps no
previous tree: the replaced release is the commit HEAD named
(replaced_ref), which --abandon checks out again and rollback returns to.
While a release is staged, the candidate is proved disjoint from staging
(D8) before any transaction opens or is superseded: from a scratch clone
of the commit, or from the git slot itself when promoting it.
"""
from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from boxmunge.commands.deploy_steps import snapshot_live_release
from boxmunge.commands.deploy_tree import TreeDeploy, report_left_open, switch_and_close
from boxmunge.crashpoint import crash_point
from boxmunge.data_dirs import ReleaseStateError
from boxmunge.git_slot import GitRefError, checkout_detached, head_sha, materialise
from boxmunge.intake import IntakeError, validate_release_tree
from boxmunge.manifest import ManifestError, load_manifest
from boxmunge.release_txn import (
    InstallTxn, advance, close_txn, load_txn, open_txn, options_text, stale_reason,
    start_refusal, supersede_txn,
)
from boxmunge.log import log_error
from boxmunge.staged_release import has_slot, sweep_debris
from boxmunge.staging_copies import slot_made
from boxmunge.staging_isolation import StagingIsolationError, check_install_isolation
from boxmunge.state import read_state

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


@dataclass(frozen=True)
class GitDeploy:
    sha: str
    source: str                     # "git" | "staged"
    staged_id: str | None = None
    component: str = "deploy"
    no_snapshot: bool = False
    candidate: Path | None = None   # the commit already materialised (a git slot's release)
    on_installed: Callable[[], None] | None = None
    on_switched: Callable[[int], None] | None = None  # after replace_release returns


def deploy_git_locked(project_name: str, paths: BoxPaths, req: GitDeploy) -> int:
    """The git-deploy core. Caller holds the project lock; never takes it."""
    try:
        sweep_debris(paths, project_name)
        txn = load_txn(paths, project_name)
    except (OSError, ReleaseStateError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    if txn is not None:
        stale = stale_reason(paths, project_name, txn)
        if stale or txn.abandoning:
            print(f"ERROR: {start_refusal(project_name, txn, stale)}.", file=sys.stderr)
            return 1
        if (txn.source, txn.ref, txn.staged_id) == (req.source, req.sha, req.staged_id):
            print(f"Resuming the install of {req.sha} from {txn.phase}; the snapshot taken "
                  f"before it ({txn.snapshot or 'none'}) is reused.")
            return _checkout_and_switch(project_name, paths, req, txn)
    advice = ("The staged release itself conflicts with staging: stage a fixed release, "
              "then promote it." if req.source == "staged" else
              "Fix the release, or unstage first.")
    if not prove_disjoint_git(project_name, paths, req.sha, req.candidate, advice=advice):
        return 1
    if txn is not None:
        forward = _fix_forward(project_name, paths, req, txn)
        if isinstance(forward, int):
            return forward
        txn = forward
    if txn is None:
        opened = _open(project_name, paths, req)
        if isinstance(opened, int):
            return opened
        txn = opened
    return _checkout_and_switch(project_name, paths, req, txn)


def prove_disjoint_git(project_name: str, paths: BoxPaths, sha: str,
                       candidate: Path | None = None, *, advice: str) -> bool:
    """D8 for a git install while a release is staged: the commit's
    production model must share nothing with the slot's staging. The
    scratch clone lies in .releases/ as ``.isolation-*`` (swept as debris)."""
    if not has_slot(paths, project_name):
        return True
    try:
        if candidate is not None:
            _prove(paths, project_name, candidate)
        else:
            with tempfile.TemporaryDirectory(dir=paths.project_releases(project_name),
                                             prefix=".isolation-") as scratch:
                os.chmod(scratch, 0o755)  # made 0700; as root, git runs as deploy below it
                release = Path(scratch) / "release"
                release.mkdir()
                materialise(paths.project_dir(project_name), sha, release,
                            made=slot_made(paths, project_name))
                _prove(paths, project_name, release)
    except (StagingIsolationError, GitRefError, ManifestError, ReleaseStateError,
            OSError) as e:
        print(f"ERROR: {e}\n  Nothing was changed. {advice}", file=sys.stderr)
        return False
    return True


def _prove(paths: BoxPaths, project_name: str, release: Path) -> None:
    check_install_isolation(paths, project_name, release,
                            load_manifest(release / "manifest.yml"))


def _open(project_name: str, paths: BoxPaths, req: GitDeploy) -> InstallTxn | int:
    # A project added with add-git-project has its checkout and manifest
    # before its first deploy, but nothing runs yet: a first deploy replaces
    # no release (no rollback target, no snapshot), as a bundle's does.
    deployed = "current_ref" in read_state(paths.project_deploy_state(project_name))
    try:
        replaced = head_sha(paths.project_dir(project_name) / "repo") if deployed else None
    except GitRefError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    snapshot = snapshot_live_release(project_name, paths, req.no_snapshot) if deployed else None
    crash_point("txn.before_open")
    try:
        txn = open_txn(paths, project_name, source=req.source, ref=req.sha,
                       replaced_ref=replaced, staged_id=req.staged_id, snapshot=snapshot or "")
    except (GitRefError, OSError) as e:
        print(f"ERROR: Recording the install of {req.sha} failed: {e}. Nothing was changed "
              f"(the snapshot {snapshot or 'none'} was kept); deploy again once the cause "
              f"is fixed.", file=sys.stderr)
        log_error(req.component, f"Opening the install of {req.sha} failed: {e}", paths,
                  project=project_name)
        return 1
    crash_point("txn.committed")
    return txn


def _fix_forward(project_name: str, paths: BoxPaths, req: GitDeploy,
                 old: InstallTxn) -> InstallTxn | None | int:
    """A different commit over an open install (spec: fix-forward). None:
    the old one was closed (nothing was checked out) and a fresh one opens;
    an exit code: recording it failed, and the old one is as it was."""
    try:
        return _supersede(project_name, paths, req, old)
    except (GitRefError, OSError, ReleaseStateError) as e:
        print(f"ERROR: Deploying {req.sha} over the unfinished install of {old.ref} could "
              f"not be recorded: {e}. That install is as it was: "
              f"{options_text(project_name, old)}.", file=sys.stderr)
        log_error(req.component, f"Superseding the install of {old.ref} failed: {e}", paths,
                  project=project_name)
        return 1


def _supersede(project_name: str, paths: BoxPaths, req: GitDeploy,
               old: InstallTxn) -> InstallTxn | None:
    if old.source == "rollback":
        # Its target is now this deploy's replaced release; from data_restored
        # the data is the target's, so a new snapshot pairs with it.
        snapshot = (snapshot_live_release(project_name, paths, req.no_snapshot) or ""
                    if old.reached("data_restored") else old.snapshot)
        replaced = old.ref
    elif not old.reached("previous_kept"):
        print(f"Closing the unfinished install of {old.ref} (nothing was checked out); "
              f"deploying {req.sha} instead.")
        close_txn(paths, project_name, old)
        return None
    else:
        snapshot, replaced = old.snapshot, old.replaced_ref
    print(f"Deploying {req.sha} over the unfinished install of {old.ref}. The rollback "
          f"target stays {replaced}, paired with {snapshot or 'no data snapshot'}.")
    return supersede_txn(paths, project_name, old, source=req.source, ref=req.sha,
                         replaced_ref=replaced, staged_id=req.staged_id, snapshot=snapshot,
                         phase="previous_kept")


def _checkout_and_switch(project_name: str, paths: BoxPaths, req: GitDeploy,
                         txn: InstallTxn) -> int:
    tree_req = TreeDeploy(tree=None, ref=req.sha, source=req.source, manifest={},
                          staged_id=req.staged_id, component=req.component,
                          on_switched=req.on_switched)
    try:
        if not txn.reached("previous_kept"):
            txn = advance(paths, project_name, txn, "previous_kept")  # git keeps no previous tree
    except (GitRefError, OSError) as e:
        return report_left_open(project_name, paths, txn, tree_req,
                                f"recording its progress failed: {e}")
    crash_point("txn.previous_kept")
    try:  # idempotent, so a resume at any phase makes sure the tree is the SHA
        checkout_detached(paths.project_dir(project_name) / "repo", req.sha)
    except GitRefError as e:
        return report_left_open(project_name, paths, txn, tree_req,
                                f"checking out {req.sha} failed: {e}")
    try:
        if not txn.reached("installed"):
            txn = advance(paths, project_name, txn, "installed")
    except (GitRefError, OSError) as e:
        return report_left_open(project_name, paths, txn, tree_req,
                                f"{req.sha} is checked out, but recording that failed: {e}")
    crash_point("txn.installed")
    if req.on_installed is not None:
        req.on_installed()
    try:
        manifest = validate_release_tree(paths.project_dir(project_name), project_name,
                                         paths, req.component)
    except IntakeError as e:
        return report_left_open(project_name, paths, txn, tree_req, str(e), e.exit_code)
    return switch_and_close(project_name, paths, replace(tree_req, manifest=manifest), txn)
