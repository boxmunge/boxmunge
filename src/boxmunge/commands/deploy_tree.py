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
reusing the recorded snapshot. While a release is staged, a new install
(fresh or fix-forward) first proves itself disjoint from staging (D8).
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
from boxmunge.intake import IntakeError, report_refusal, validate_release_tree
from boxmunge.log import log_error
from boxmunge.release import (
    install_release, live_ref, load_previous_release, mark_live, sync_release_code,
)
from boxmunge.release_keep import (
    ensure_kept_pairing, keep_previous_release_txn, restore_superseded,
)
from boxmunge.release_txn import (
    InstallTxn, advance, close_txn, load_txn, open_txn, options_text, stale_reason,
    start_refusal, supersede_txn,
)
from boxmunge.staged_release import sweep_debris
from boxmunge.staging_isolation import StagingIsolationError, check_install_isolation

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
        sweep_debris(paths, project_name)
        txn = load_txn(paths, project_name)
        if txn is not None and not stale_reason(paths, project_name, txn):
            ensure_kept_pairing(paths, project_name, txn)
    except (OSError, ReleaseStateError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    if txn is not None:
        stale = stale_reason(paths, project_name, txn)
        if stale or txn.abandoning:
            print(f"ERROR: {start_refusal(project_name, txn, stale)}.", file=sys.stderr)
            return 1
        if (txn.source, txn.ref, txn.staged_id) == (req.source, req.ref, req.staged_id):
            return _resume(project_name, paths, req, txn)
        return _fix_forward(project_name, paths, req, txn)
    return _fresh(project_name, paths, req)


def _prove_disjoint(project_name: str, paths: BoxPaths, req: TreeDeploy) -> bool:
    """D8: while a release is staged, production's next release must share
    nothing with staging. Checked before the transaction commits."""
    if req.tree is None:
        return True
    try:
        check_install_isolation(paths, project_name, req.tree, req.manifest)
    except (StagingIsolationError, OSError) as e:
        print(f"ERROR: {e}\n  Nothing was changed. Fix the release, or unstage first.",
              file=sys.stderr)
        return False
    return True


def _fresh(project_name: str, paths: BoxPaths, req: TreeDeploy) -> int:
    if not _prove_disjoint(project_name, paths, req):
        return 1
    return _open(project_name, paths, req)


def _open(project_name: str, paths: BoxPaths, req: TreeDeploy) -> int:
    deployed = (paths.project_dir(project_name) / "manifest.yml").exists()
    try:
        replaced = live_ref(paths, project_name) if deployed else None
    except ReleaseStateError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
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
            sync_release_code(paths.project_dir(project_name))
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
    print(f"ERROR: The install of {req.ref} stopped at {txn.phase}: {why}. This attempt "
          f"did not start or change production's containers, and other starts of "
          f"{project_name} are refused until this install is finished: "
          f"{options_text(project_name, txn)}.", file=sys.stderr)
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
    """A different deploy over an open install (spec: fix-forward). The
    isolation proof comes first: a refused deploy leaves the open install
    exactly as it was."""
    if not _prove_disjoint(project_name, paths, req):
        return 1
    if old.source == "rollback":
        return _over_rollback(project_name, paths, req, old)
    if not old.reached("previous_kept"):
        print(f"Closing the unfinished install of {old.ref} (nothing was installed); "
              f"deploying {req.ref} instead.")
        restore_superseded(paths, project_name, old)
        close_txn(paths, project_name, old)
        return _open(project_name, paths, req)
    print(f"Deploying {req.ref} over the unfinished install of {old.ref}. The rollback "
          f"target stays {old.replaced_ref or 'none (first deploy)'}, paired with "
          f"{old.snapshot or 'no data snapshot'}; no new snapshot is taken.")
    txn = supersede_txn(paths, project_name, old, source=req.source, ref=req.ref,
                        replaced_ref=old.replaced_ref, staged_id=req.staged_id,
                        snapshot=old.snapshot, phase="previous_kept")
    ensure_kept_pairing(paths, project_name, txn)
    return _install(project_name, paths, req, txn)


def _over_rollback(project_name: str, paths: BoxPaths, req: TreeDeploy,
                   old: InstallTxn) -> int:
    """Superseding a rollback: its target (still in previous/) becomes this
    deploy's replaced release. Before data_restored the data is still the
    failed release's, so the target's own snapshot pairs with it; from
    data_restored on a new snapshot is taken."""
    target = load_previous_release(paths, project_name)
    if target is None:
        print(f"ERROR: The interrupted rollback of {project_name} has no target left in "
              f".releases/previous/; rerun 'rollback {project_name}' or inspect it.",
              file=sys.stderr)
        return 1
    snapshot = (snapshot_live_release(project_name, paths, req.no_snapshot) or ""
                if old.reached("data_restored") else old.snapshot)
    # Recorded first, then paired: a crash between the two is repaired by
    # ensure_kept_pairing before anything reads the rollback target.
    txn = supersede_txn(paths, project_name, old, source=req.source, ref=req.ref,
                        replaced_ref=target.ref, staged_id=req.staged_id,
                        snapshot=snapshot, phase="previous_kept")
    ensure_kept_pairing(paths, project_name, txn)
    return _install(project_name, paths, req, txn)


def _names(project_name: str, ref: str | None, txn_ref: str) -> bool:
    if ref is None:
        return True
    wanted = ref.removesuffix(".tar.gz")
    return wanted == txn_ref or txn_ref.removeprefix(f"{project_name}-").startswith(wanted)


def bundle_resume_problem(project_name: str, paths: BoxPaths, txn: InstallTxn,
                          ref: str | None) -> str | None:
    """Why `prod-deploy` without a bundle cannot resume ``txn``, or None.
    Only a bundle install whose code is in place (live.json names it) can
    resume from the project dir."""
    stale = stale_reason(paths, project_name, txn)
    if stale or txn.abandoning or txn.source != "bundle" \
            or not _names(project_name, ref, txn.ref):
        return start_refusal(project_name, txn, stale)
    if not txn.reached("installed"):
        return (f"The install of {txn.ref} cannot be resumed: its bundle is no longer in "
                f"the inbox and the install had not finished (phase {txn.phase}). Upload "
                f"{txn.ref}.tar.gz again and rerun "
                f"'prod-deploy {project_name} --ref {txn.ref}'; or "
                f"{options_text(project_name, txn, rerun=False)}")
    try:
        installed = live_ref(paths, project_name)
    except ReleaseStateError as e:
        return str(e)
    if installed != txn.ref:
        return (f"The install of {txn.ref} cannot be resumed from the project dir: "
                f"live.json names {installed}. {options_text(project_name, txn, rerun=False)}")
    return None


def resume_without_bundle(project_name: str, paths: BoxPaths, txn: InstallTxn,
                          ref: str | None, component: str) -> int:
    """`prod-deploy` found no bundle while an install is open: a bundle
    install that reached `installed` resumes from the project dir."""
    problem = bundle_resume_problem(project_name, paths, txn, ref)
    if problem:
        print(f"ERROR: {problem}.", file=sys.stderr)
        return 1
    try:
        manifest = validate_release_tree(paths.project_dir(project_name), project_name,
                                         paths, component)
    except IntakeError as e:
        return report_refusal(e)
    return deploy_tree_locked(project_name, paths, TreeDeploy(
        tree=None, ref=txn.ref, source="bundle", manifest=manifest, component=component))
