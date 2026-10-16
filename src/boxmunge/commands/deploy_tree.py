# SPDX-License-Identifier: Apache-2.0
"""deploy_tree_locked: install a release tree in production, inside an
install transaction (release_txn).

The same core runs a bundle deploy and a promote (whose tree is the
staged slot). The phases and what happens at each failure point are the
spec's closing table: a failed keep closes the transaction with nothing
changed; a failed install, hook or config generation leaves it open (rerun,
--abandon before hook_started, rollback from hook_started on, or a
different deploy); once replace_release returns, it is closed whatever the
result. A rerun of the same source and ref resumes from the recorded phase,
reusing the recorded snapshot.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from boxmunge.commands.deploy import (
    generate_release_config, replace_release, run_pre_deploy_hook,
)
from boxmunge.commands.deploy_steps import snapshot_live_release
from boxmunge.crashpoint import crash_point
from boxmunge.data_dirs import ReleaseStateError, SetAsideError, log_kept, set_aside_announcer
from boxmunge.log import log_error
from boxmunge.release import install_release, live_ref, mark_live
from boxmunge.release_keep import keep_previous_release_txn, restore_superseded
from boxmunge.release_txn import (
    InstallTxn, advance, close_txn, load_txn, open_txn, options_text, stale_reason,
    start_refusal,
)

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


@dataclass(frozen=True)
class TreeDeploy:
    tree: Path | None          # the release to install; None resumes from the project dir
    ref: str
    source: str                # "bundle" | "staged"
    manifest: dict
    staged_id: str | None = None
    component: str = "deploy"
    no_snapshot: bool = False
    on_installed: Callable[[], None] | None = None   # after the code is in place
    on_switched: Callable[[int], None] | None = None  # after replace_release returns


def deploy_tree_locked(project_name: str, paths: BoxPaths, req: TreeDeploy) -> int:
    """The tree-deploy core. Caller holds the project lock; never takes it."""
    try:
        txn = load_txn(paths, project_name)
    except ReleaseStateError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    if txn is not None:
        stale = stale_reason(paths, project_name, txn)
        if stale:
            print(f"ERROR: {start_refusal(project_name, txn, stale)}.", file=sys.stderr)
            return 1
        if (txn.source, txn.ref, txn.staged_id) == (req.source, req.ref, req.staged_id):
            return _resume(project_name, paths, req, txn)
        return _fix_forward(project_name, paths, req, txn)
    return _fresh(project_name, paths, req)


def _fresh(project_name: str, paths: BoxPaths, req: TreeDeploy) -> int:
    deployed = (paths.project_dir(project_name) / "manifest.yml").exists()
    replaced = live_ref(paths, project_name) if deployed else None
    snapshot = snapshot_live_release(project_name, paths, req.no_snapshot) if deployed else None
    crash_point("txn.before_open")
    txn = open_txn(paths, project_name, source=req.source, ref=req.ref,
                   replaced_ref=replaced, staged_id=req.staged_id, snapshot=snapshot or "")
    crash_point("txn.committed")
    return _keep(project_name, paths, req, txn)


def _keep(project_name: str, paths: BoxPaths, req: TreeDeploy, txn: InstallTxn) -> int:
    if txn.replaced_ref is not None:
        try:
            restore_superseded(paths, project_name, txn)  # a resume from committed
            keep_previous_release_txn(paths, project_name, txn, req.tree)
        except (OSError, ReleaseStateError) as e:
            restore_superseded(paths, project_name, txn)
            close_txn(paths, project_name, txn)
            changed = ("Only the old contents named above were moved; nothing else"
                       if isinstance(e, SetAsideError) else "Nothing")
            print(f"ERROR: Keeping the previous release failed: {e}\n  {changed} in the "
                  f"project was changed. Deploy again once the cause is fixed.",
                  file=sys.stderr)
            log_error(req.component, f"Keeping the previous release failed: {e}",
                      paths, project=project_name)
            return 1
    txn = advance(paths, project_name, txn, "previous_kept")
    crash_point("txn.previous_kept")
    return _install(project_name, paths, req, txn)


def _install(project_name: str, paths: BoxPaths, req: TreeDeploy, txn: InstallTxn) -> int:
    if req.tree is not None:
        try:
            kept = install_release(req.tree, paths.project_dir(project_name),
                                   set_aside_announcer(paths, project_name, req.component))
            mark_live(paths, project_name, req.ref)
            log_kept(paths, project_name, kept, req.component)
        except (OSError, ValueError) as e:
            return _left_open(project_name, paths, txn, req, f"installing the release failed: {e}")
    elif not txn.reached("installed"):
        return _left_open(project_name, paths, txn, req,
                          f"the release {req.ref} is no longer available to install, and "
                          f"its install had not finished")
    if not txn.reached("installed"):
        txn = advance(paths, project_name, txn, "installed")
    crash_point("txn.installed")
    if req.on_installed is not None:
        req.on_installed()
    return _switch(project_name, paths, req, txn)


def _switch(project_name: str, paths: BoxPaths, req: TreeDeploy, txn: InstallTxn) -> int:
    resumed_switch = txn.reached("switching")
    if not resumed_switch:
        if not txn.reached("hook_started"):
            txn = advance(paths, project_name, txn, "hook_started")
        crash_point("txn.hook_started")
        print(f"Deploying {project_name} (ref: {req.ref})...")
        rc = run_pre_deploy_hook(project_name, paths, req.manifest)
        if rc != 0:
            return _left_open(project_name, paths, txn, req, "the pre-deploy hook failed", rc)
    try:
        generate_release_config(project_name, paths, req.manifest, req.component)
    except (OSError, ValueError) as e:
        return _left_open(project_name, paths, txn, req, f"generating its configs failed: {e}")
    if not resumed_switch:
        txn = advance(paths, project_name, txn, "switching")
    else:
        print(f"Finishing the interrupted install of {req.ref}: production may now run "
              f"it, so its pre-deploy hook is not run again and no new snapshot is taken.")
    crash_point("txn.switching")
    rc = replace_release(project_name, paths, req.manifest, req.ref, txn.snapshot or None,
                         component=req.component, txn=txn.id)
    crash_point("txn.replaced")
    if req.on_switched is not None:
        req.on_switched(rc)
    crash_point("txn.switched")
    close_txn(paths, project_name, txn)
    return rc


def _left_open(project_name: str, paths: BoxPaths, txn: InstallTxn, req: TreeDeploy,
               why: str, rc: int = 1) -> int:
    print(f"ERROR: The install of {req.ref} stopped at {txn.phase}: {why}. Production's "
          f"containers were not started or changed, and other starts of {project_name} "
          f"are refused until this install is finished: {options_text(project_name, txn)}.",
          file=sys.stderr)
    log_error(req.component, f"Install of {req.ref} left open at {txn.phase}: {why}",
              paths, project=project_name)
    return rc


def _resume(project_name: str, paths: BoxPaths, req: TreeDeploy, txn: InstallTxn) -> int:
    print(f"Resuming the install of {req.ref} from {txn.phase}; the snapshot taken "
          f"before it ({txn.snapshot or 'none'}) is reused.")
    if txn.phase == "committed":
        return _keep(project_name, paths, req, txn)
    if txn.phase == "switching":
        return _switch(project_name, paths, req, txn)
    return _install(project_name, paths, req, txn)


def _fix_forward(project_name: str, paths: BoxPaths, req: TreeDeploy,
                 old: InstallTxn) -> int:
    """A different deploy over an open install. Until Task 6 makes it a
    fix-forward, it is refused with the open install's options."""
    print(f"ERROR: {start_refusal(project_name, old, None)}.", file=sys.stderr)
    return 1
