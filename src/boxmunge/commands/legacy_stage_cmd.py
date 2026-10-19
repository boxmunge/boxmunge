# SPDX-License-Identifier: Apache-2.0
"""boxmunge-server legacy-stage <project> [--discard [--confirm-recreated] | --keep-staged]

Resolves a release staged by boxmunge 0.10.1 (see legacy_stage and
legacy_stage_ops). Operator-only: it runs as root, outside the deploy shell.
"""
from __future__ import annotations

import sys
from contextlib import nullcontext
from typing import TYPE_CHECKING

from boxmunge.commands.upgrade_steps import UpgradeGateError
from boxmunge.compose_guard import ComposeRefused
from boxmunge.docker_run import DockerError
from boxmunge.fileutil import LockError, project_lock
from boxmunge.legacy_stage import (
    Evidence, EvidenceError, LegacyStage, cannot_tell, evidence, get_record, legacy_stage,
    update_record,
)
from boxmunge.legacy_stage_ops import (
    LegacyStageError, allowed_choices, drop_stage_record, finish_apply,
    platform_rollback_possible, predeploy_snapshots, report_resolved, resolve,
)
from boxmunge.lifecycle import migration_refusal
from boxmunge.manifest import ManifestError
from boxmunge.migration import MigrationError
from boxmunge.state import StateError
from boxmunge.upgrade_state import UpgradeInProgress, UpgradeStateError, upgrade_lock

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

# What a step can fail with. GitRefError, ReleaseStateError and ComposeError
# are ValueErrors; ComposeRefused and the data helper's errors DockerErrors;
# UpgradeGateError an unwritable maintenance page.
STEP_ERRORS = (DockerError, OSError, ValueError, LegacyStageError, ManifestError,
               MigrationError, StateError, UpgradeGateError)


def _step_failed(e: Exception) -> int:
    """A refused start needs its cause fixed first; anything else a rerun finishes."""
    advice = ("Fix what it refuses, then run the same command again" if isinstance(e, ComposeRefused)
              else "Run the same command again to finish")
    print(f"ERROR: {e}. {advice}.", file=sys.stderr)
    return 1


def _show(project: str, stage: LegacyStage, ev: Evidence | None) -> None:
    print(f"{project}: a release staged by boxmunge 0.10.1 ({stage.kind}).")
    lines = (ev.describe() if ev else
             ["production runs the release a 0.10.1 promote installed; staging was left "
              "behind"] if stage.kind == "leftover" else
             ["a --discard of it was started; the evidence is not read again"])
    for line in lines:
        print(f"  {line}")


def _choices_text(stage: LegacyStage, ev: Evidence | None) -> str:
    recreated = ev is not None and ev.classification == "recreated"
    return ", ".join(f"--{c}" + (" --confirm-recreated" if c == "discard" and recreated else "")
                     for c in allowed_choices(stage))


RECREATED_WARNING = ("production was started from the staged files, so discarding them "
                     "changes what runs, and data the staged code wrote stays")


def _restore_hint(paths: BoxPaths, project: str) -> str:
    newest = predeploy_snapshots(paths, project)
    if not newest:
        return "there is no pre-deploy snapshot"
    return (f"the newest pre-deploy snapshot is {newest[0]} (boxmunge restore {project} "
            f"{newest[0]})")


def _needs_confirmation(ev: Evidence | None, choice: str, recorded: str | None) -> bool:
    # Once recorded, the evidence no longer tells: step 4 changes what it reads.
    return (not recorded and choice == "discard" and ev is not None
            and ev.classification == "recreated")


def _refusal(paths: BoxPaths, project: str, stage: LegacyStage, ev: Evidence | None,
             choice: str, recorded: str | None, confirm_recreated: bool) -> str | None:
    allowed = allowed_choices(stage)
    if choice not in allowed:
        return (f"--{choice} is not available for this stage; use "
                f"{' or '.join('--' + c for c in allowed)}")
    if recorded and recorded != choice:
        return (f"a resolution with --{recorded} was started and must be finished: run "
                f"boxmunge-server legacy-stage {project} --{recorded}")
    if _needs_confirmation(ev, choice, recorded) and not confirm_recreated:
        return (f"{RECREATED_WARNING}; {_restore_hint(paths, project)}. To go ahead, rerun "
                f"with --discard --confirm-recreated")
    return None


def _report(paths: BoxPaths, project: str, choice: str) -> int:
    try:
        report_resolved(paths, project, choice)
    except STEP_ERRORS as e:
        print(f"ERROR: {project} is resolved, but reporting it failed: {e}.", file=sys.stderr)
        return 1
    print(f"{project}: resolved (--{choice}).")
    return 0


def _finish_resolved(paths: BoxPaths, project: str, choice: str | None,
                     recorded: str | None) -> int:
    """After step 6 the stage is no longer detected: the record finishes it."""
    if not recorded:
        print(f"ERROR: '{project}' has no release staged by boxmunge 0.10.1.", file=sys.stderr)
        return 1
    if choice != recorded:
        message = (f"{project}'s 0.10.1 stage was resolved with --{recorded} up to its last "
                   f"step; finish it with: boxmunge-server legacy-stage {project} --{recorded}")
        print(message if choice is None else f"ERROR: {message}",
              file=sys.stdout if choice is None else sys.stderr)
        return 0 if choice is None else 1
    print(f"Finishing the resolution of {project}'s 0.10.1 stage (--{recorded})...")
    try:
        drop_stage_record(paths, project)  # a stage detection lost at step 5
        finish_apply(paths, project)
    except STEP_ERRORS as e:
        return _step_failed(e)
    return _report(paths, project, recorded)


def legacy_stage_locked(paths: BoxPaths, project: str, choice: str | None,
                        confirm_recreated: bool) -> int:
    """The core. Caller holds the project lock; never takes it."""
    refusal = migration_refusal("A legacy-stage resolution", paths) if choice else None
    if refusal:
        print(f"ERROR: {refusal}", file=sys.stderr)
        return 1
    try:
        recorded = (get_record(paths, project) or {}).get("choice")
    except StateError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    try:
        stage = legacy_stage(paths, project)
    except OSError as e:
        print(f"ERROR: {cannot_tell(project, e)}", file=sys.stderr)
        return 1
    if stage is None:
        return _finish_resolved(paths, project, choice, recorded)
    why = platform_rollback_possible(paths)
    if why and choice is not None:
        print(f"ERROR: Not yet: {why}. Run it again after that.", file=sys.stderr)
        return 1
    ev = None
    # A started --discard needs no evidence, and its step 4 may have made it
    # unreadable (a never-deployed project's live.json is gone): whatever is
    # typed now reaches the resume or the refusal naming --discard.
    if stage.kind != "leftover" and recorded != "discard":
        try:
            ev = evidence(paths, project, stage)
        except EvidenceError as e:
            print(f"ERROR: Cannot tell what production runs: {e}. Fix that and run it again.",
                  file=sys.stderr)
            return 1
    _show(project, stage, ev)
    if choice is None:
        print(f"Choices: {_choices_text(stage, ev)}")
        if recorded:
            print(f"A resolution with --{recorded} was started; run it again to finish.")
        if why:
            print(f"Not available yet: {why}.")
        return 0
    refusal = _refusal(paths, project, stage, ev, choice, recorded, confirm_recreated)
    if refusal:
        print(f"ERROR: {refusal[0].upper()}{refusal[1:]}.", file=sys.stderr)
        return 1
    if _needs_confirmation(ev, choice, recorded):
        print(f"WARNING: {RECREATED_WARNING[0].upper()}{RECREATED_WARNING[1:]}; "
              f"{_restore_hint(paths, project)}.")
    if recorded:
        print(f"Resuming the resolution with --{choice}...")
    try:
        update_record(paths, project, kind=stage.kind, choice=choice)
        resolve(paths, project, stage, ev, choice)
    except STEP_ERRORS as e:
        return _step_failed(e)
    return _report(paths, project, choice)


def run_legacy_stage(paths: BoxPaths, project: str, choice: str | None,
                     confirm_recreated: bool) -> int:
    """A resolution holds upgrade.lock (lock order: outside the project lock).
    The shim holds it from before its stash until after the swap, a window no
    marker or probation shows: a resolution there would be put back by a
    rollback's stash restore. Showing the evidence needs no such guard."""
    try:
        with upgrade_lock(paths) if choice is not None else nullcontext():
            with project_lock(project, paths):
                return legacy_stage_locked(paths, project, choice, confirm_recreated)
    except UpgradeInProgress:
        print("ERROR: a platform upgrade is in progress; run it again after it finishes.",
              file=sys.stderr)
        return 1
    except UpgradeStateError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_legacy_stage(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name, usage_error
    from boxmunge.paths import BoxPaths
    parsed = parse_args("legacy-stage", args,
                        flags={"--discard", "--keep-staged", "--confirm-recreated"},
                        min_positional=1, max_positional=1)
    if parsed.has("--discard") and parsed.has("--keep-staged"):
        usage_error("legacy-stage", "choose one of --discard and --keep-staged")
    if parsed.has("--confirm-recreated") and not parsed.has("--discard"):
        usage_error("legacy-stage", "--confirm-recreated goes with --discard")
    choice = ("discard" if parsed.has("--discard") else
              "keep-staged" if parsed.has("--keep-staged") else None)
    project = require_project_name("legacy-stage", parsed.positional[0])
    sys.exit(run_legacy_stage(BoxPaths(), project, choice, parsed.has("--confirm-recreated")))
