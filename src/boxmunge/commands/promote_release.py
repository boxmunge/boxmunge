# SPDX-License-Identifier: Apache-2.0
"""Deploy the release `stage` installed (the deploy half of promote).

Once the staged release's containers start, production runs it whatever
fails afterwards. From then on the production release `stage` kept aside
becomes the previous release (the rollback target), as after any bundle
deploy, paired with the data snapshot taken before the promotion. Before
that, a failure leaves the stage untouched.

The switch is recorded in the kept release before the containers start
(release_staging.mark_prestage_replaced, with that snapshot), so a promote
that is killed part-way is finished by running promote again: the rerun
neither re-runs the pre-deploy hook nor takes a new snapshot, and however
it ends, the kept release becomes the previous release.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass

from boxmunge.commands.deploy import (
    deploy_eligible, generate_release_config, replace_release, run_pre_deploy_hook,
)
from boxmunge.commands.deploy_steps import record_deploy_state, take_pre_deploy_snapshot
from boxmunge.intake import IntakeError, report_refusal, validate_release_tree
from boxmunge.log import log_error
from boxmunge.manifest import ManifestError, load_manifest
from boxmunge.paths import BoxPaths
from boxmunge.probation import clear_probation_if_active
from boxmunge.state import read_state
from boxmunge.release import ReleaseStateError, discard_previous_release, live_ref
from boxmunge.release_txn import refuse_if_install_open
from boxmunge.release_staging import (
    discard_prestage, has_prestage, mark_prestage_replaced, prestage_ref,
    prestage_replaced, prestage_snapshot, prestage_to_previous, prestage_tree,
)

COMPONENT = "promote"


@dataclass(frozen=True)
class Promotion:
    rc: int
    switched: bool  # production was switched to the staged release


def deploy_staged_locked(project_name: str, paths: BoxPaths) -> Promotion:
    """The staged-deploy core. Caller holds the project lock; never takes it."""
    if not deploy_eligible(project_name, paths):
        return Promotion(1, switched=False)
    if refuse_if_install_open(paths, project_name, component=COMPONENT):
        return Promotion(1, switched=False)
    clear_probation_if_active(paths, "deploy")
    if not has_prestage(paths, project_name):
        print(f"ERROR: No staged release is installed for '{project_name}'.",
              file=sys.stderr)
        return Promotion(1, switched=False)
    try:
        if prestage_replaced(paths, project_name):
            return _finish_switched(project_name, paths)
        return _promote(project_name, paths)
    except ReleaseStateError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return Promotion(1, switched=False)


def _promote(project_name: str, paths: BoxPaths) -> Promotion:
    try:
        manifest = validate_release_tree(paths.project_dir(project_name),
                                         project_name, paths, COMPONENT)
    except IntakeError as e:
        return Promotion(report_refusal(e), switched=False)
    staged_ref = live_ref(paths, project_name)
    # Production data is snapshotted with the production release's own
    # backup config: that snapshot is what rollback pairs with it.
    snapshot = None
    if prestage_ref(paths, project_name) is not None:
        try:
            production = load_manifest(prestage_tree(paths, project_name) / "manifest.yml")
        except ManifestError as e:
            print(f"ERROR: Cannot read the kept production release: {e}", file=sys.stderr)
            return Promotion(1, switched=False)
        snapshot = take_pre_deploy_snapshot(project_name, paths, production, False)
    print(f"Deploying {project_name} (ref: {staged_ref})...")
    rc = run_pre_deploy_hook(project_name, paths, manifest)
    if rc != 0:
        return Promotion(rc, switched=False)
    generate_release_config(project_name, paths, manifest, COMPONENT)
    # Recorded before the containers start: see the module docstring.
    mark_prestage_replaced(paths, project_name, snapshot)
    return _switch(project_name, paths, staged_ref, snapshot,
                   lambda: replace_release(project_name, paths, manifest, staged_ref,
                                           snapshot, component=COMPONENT, promoting=True),
                   certain=True)


def _finish_switched(project_name: str, paths: BoxPaths) -> Promotion:
    """Rerun of a promote killed after it switched production."""
    staged_ref = live_ref(paths, project_name)
    snapshot = prestage_snapshot(paths, project_name)
    print(f"Finishing the interrupted promotion of {staged_ref}: production already "
          f"runs it, so its pre-deploy hook is not run again and no new snapshot "
          f"is taken.")

    first_deploy = "current_ref" not in read_state(paths.project_deploy_state(project_name))

    def restart() -> int:
        try:
            manifest = validate_release_tree(paths.project_dir(project_name),
                                             project_name, paths, COMPONENT)
        except IntakeError as e:
            return report_refusal(e)
        generate_release_config(project_name, paths, manifest, COMPONENT)
        return replace_release(project_name, paths, manifest, staged_ref, snapshot,
                               component=COMPONENT, promoting=True)

    try:
        # The killed run may or may not have reached its first container
        # start: say so, rather than claim the switch happened.
        return _switch(project_name, paths, staged_ref, snapshot, restart, certain=False)
    finally:
        # The release history now treats production as switched, so the
        # deploy state does too, as replace_release records once containers
        # may have started (recording the current ref again is a no-op).
        if not first_deploy:
            record_deploy_state(paths, project_name, staged_ref, snapshot)


def _switch(project_name: str, paths: BoxPaths, staged_ref: str,
            snapshot: str | None, start, *, certain: bool) -> Promotion:
    """Run ``start`` (production runs the staged release from its first
    container start); whatever happens, keep the production release as the
    previous one."""
    try:
        rc = start()
    except BaseException:
        _keep_replaced_release(project_name, paths, snapshot, staged_ref)
        raise
    kept = _keep_replaced_release(project_name, paths, snapshot, staged_ref)
    if rc != 0:
        report_failed_after_switch(project_name, paths, staged_ref, certain)
        return Promotion(rc, switched=True)
    return Promotion(0 if kept else 1, switched=True)


def _keep_replaced_release(project_name: str, paths: BoxPaths,
                           snapshot: str | None, staged_ref: str) -> bool:
    """The kept production release becomes the previous release (the
    rollback target), exactly as a bundle deploy keeps the release it
    replaces. False if that failed."""
    try:
        prestage_to_previous(paths, project_name, snapshot, staged_ref)
        return True
    except (OSError, ReleaseStateError) as e:
        print(f"ERROR: {staged_ref} is running in production, but keeping the "
              f"release it replaced failed: {e}. 'rollback {project_name}' is "
              f"not available for this deploy.", file=sys.stderr)
        log_error("deploy", f"Keeping the previous release failed: {e}",
                  paths, project=project_name)
    # A kept production release left behind would let unstage put old files
    # under the new containers, and an older previous release would pair
    # the wrong code with the data: drop both.
    try:
        discard_prestage(paths, project_name)
        discard_previous_release(paths, project_name)
    except (OSError, ReleaseStateError) as cleanup_error:
        print(f"ERROR: Could not remove .releases/prestage/: {cleanup_error}. "
              f"Remove it by hand before running 'unstage {project_name}'.",
              file=sys.stderr)
    return False


def report_failed_after_switch(project_name: str, paths: BoxPaths,
                                staged_ref: str, certain: bool) -> None:
    # rollback imports deploy, which this module also builds on: imported
    # here, where it is needed, rather than at module load.
    from boxmunge.commands.rollback import RollbackUnavailable, find_rollback_target
    runs = "now runs" if certain else "may now run"
    print(f"ERROR: The promotion failed after production was switched: "
          f"production {runs} {staged_ref}.", file=sys.stderr)
    try:
        target = find_rollback_target(paths, project_name)
    except RollbackUnavailable as e:
        print(f"  'rollback {project_name}' is not available: {e}. Fix the cause "
              f"and deploy again.", file=sys.stderr)
    else:
        data = (f"restores the data snapshot {target.snapshot} taken before the "
                f"promotion" if target.snapshot
                else "has no data to restore (backup.type: none)")
        print(f"  'rollback {project_name}' returns to {target.ref} and {data}. "
              f"Or fix the cause and deploy again.", file=sys.stderr)
    log_error("deploy", f"Promotion of {staged_ref} failed after production "
              f"was switched to it", paths, project=project_name)
