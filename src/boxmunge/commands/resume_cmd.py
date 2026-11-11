# SPDX-License-Identifier: Apache-2.0
"""boxmunge resume <project> — bring a paused project back online safely.

By default, pulls the latest images for all `image:` services before
starting the project. This closes the window where a long-paused project
could come back online with stale, vulnerable container images.

The --skip-security-checks flag bypasses the pre-resume image pull. Use
only when the operator explicitly accepts the risk (e.g., registry outage).
"""
from __future__ import annotations

import sys


from boxmunge.commands.confirm import confirm
from boxmunge.bind_sources import BindSourceError
from boxmunge.caddy import prepare_caddy_config
from boxmunge.compose import prepare_compose_override
from boxmunge.run_as import RunAsError
from boxmunge.user_drift import guard_pull, image_ids
from boxmunge.compose_guard import (
    ComposeRefused, check_start, compose_up_checked, stale_containers,
)
from boxmunge.compose_up_steps import ComposeUpFailed
from boxmunge.deployed_inventory import (
    InventoryError, load_deployed_inventory, pulled_services,
)
from boxmunge.docker import compose_pull, caddy_reload, DockerError
from boxmunge.fileutil import LockError, project_lock
from boxmunge.health_checks.smoke import run_smoke
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.lifecycle import BlockReason, is_blocked, paused_refusal
from boxmunge.legacy_stage import refuse_if_legacy_stage
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.pause import (
    awaiting_deploy, clear_paused_state, is_paused,
    mark_awaiting_deploy, mark_pause_incomplete, pause_incomplete,
    release_restart_policies, stop_again,
)
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.redeploy_hint import redeploy_command
from boxmunge.release_txn import open_install_reason
from boxmunge.state import read_state, write_state


def _services_to_pull(project_name: str, paths: BoxPaths) -> dict[str, str]:
    """{service: image} a resume pulls: the services `up` starts from a
    registry image (deployed_inventory.pulled_services). Raises InventoryError."""
    inventory = load_deployed_inventory(
        paths.project_dir(project_name), _compose_files(project_name, paths), project_name,
    )
    return {name: str(svc.image) for name, svc in sorted(pulled_services(inventory).items())}


def _refuse_unless_resumable(project_name: str, paths: BoxPaths) -> bool:
    """Print why and return False unless the project is paused, not quarantined."""
    # Pause-resume must NOT silently un-quarantine. Lifting CVE quarantine
    # has its own dedicated command path (`boxmunge security resume`)
    # which re-scans before lifting. is_blocked() returns QUARANTINED
    # first if both states exist (quarantine wins), so the refuse
    # message is the security one.
    block = is_blocked(project_name, paths)
    if block and block.reason in (BlockReason.QUARANTINED, BlockReason.MIGRATING):
        refusal = (paused_refusal(project_name, block) if is_paused(project_name, paths)
                   else block.refuse_message)
        print(f"ERROR: {refusal}", file=sys.stderr)
        return False
    # Positive precondition: this command can only be invoked when the
    # project is paused.
    if not is_paused(project_name, paths):
        print(f"ERROR: Project '{project_name}' is not paused.",
              file=sys.stderr)
        return False
    return True


def _compose_files(project_name: str, paths: BoxPaths) -> list[str]:
    compose_files = ["compose.yml"]
    if paths.project_compose_override(project_name).exists():
        compose_files.append("compose.boxmunge.yml")
    return compose_files


def run_resume(
    project_name: str,
    paths: BoxPaths,
    yes: bool = False,
    skip_security_checks: bool = False,
    no_start: bool = False,
) -> int:
    """Resume a paused project. Returns 0 on success, 1 on failure.

    ``no_start`` (`--no-start`) starts nothing: it hands the pause to the
    next deploy (hand_to_deploy_locked).

    Preconditions are checked before the confirmation prompt (so the
    operator is not asked to confirm something that cannot happen) and
    again under the project lock, which the resume itself holds: a
    quarantine landing while the operator answered the prompt wins.
    """
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists() or not (project_dir / "manifest.yml").exists():
        print(f"ERROR: Project not found: {project_name}", file=sys.stderr)
        return 1
    if no_start:
        try:
            with project_lock(project_name, paths):
                return hand_to_deploy_locked(project_name, paths)
        except LockError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
    if not _refuse_unless_resumable(project_name, paths):
        return 1

    if not yes:
        try:
            pull_image_services = _services_to_pull(project_name, paths)
        except InventoryError as e:
            print(f"ERROR: cannot read the project's services: {e}", file=sys.stderr)
            return 1
        print(f"This will resume '{project_name}':")
        if skip_security_checks:
            print("  - SKIPPING image pull (--skip-security-checks set)")
        elif pull_image_services:
            print("  - Pull latest images (security check)")
        else:
            print("  - No image: services to pull")
        print("  - Start containers")
        print("  - Restore Caddy routing + run smoke test")
        if not confirm("resume"):
            return 1

    try:
        with project_lock(project_name, paths):
            rc, smoke_failure = resume_locked(
                project_name, paths, skip_security_checks,
            )
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    # Alert after releasing the lock: Pushover is a network call.
    if smoke_failure is not None:
        _alert_smoke_failed(project_name, paths, smoke_failure)
    return rc


def resume_locked(
    project_name: str, paths: BoxPaths, skip_security_checks: bool,
) -> tuple[int, str | None]:
    """Bring the project back online. Caller holds the project lock.

    Returns the exit code and, if the post-resume smoke test failed, its
    message, so the caller can alert after releasing the lock.
    """
    if refuse_if_legacy_stage(paths, project_name):
        return 1, None
    if not _refuse_unless_resumable(project_name, paths):
        return 1, None
    install = open_install_reason(paths, project_name)
    if install is not None:
        print(f"ERROR: {project_name} cannot be resumed while its install is open "
              f"(nothing may start production but the install): {install}. Those are "
              f"refused while it is paused: run `boxmunge resume {project_name} "
              f"--no-start` first, which hands the pause to the install's deploy.",
              file=sys.stderr)
        return 1, None
    project_dir = paths.project_dir(project_name)
    try:
        manifest = load_manifest(paths.project_manifest(project_name))
    except ManifestError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1, None
    # The start runs this release's overlay, so it is regenerated first and
    # the checks below see what will run (it may mount differently from the
    # one the project was paused on).
    try:
        prepare_compose_override(paths, manifest, component="resume")
    except (OSError, ValueError, DockerError, BindSourceError) as e:
        print(f"ERROR: cannot regenerate the compose overlay: {e}. "
              f"{_deploy_hint(project_name, paths)}", file=sys.stderr)
        log_error("resume", f"Overlay regeneration failed: {e}", paths, project=project_name)
        return 1, None
    compose_files = _compose_files(project_name, paths)

    # Check compose.yml and the bind sources BEFORE any container action. A
    # hostile compose.yml introduced while the project was paused must not
    # survive even an image pull or the release of its restart policies
    # (audit A-NEW-1); the start below runs on this check only while every
    # file it read is unchanged, and checks again otherwise. Containers made before
    # the own-file rules are recreated from the checked files, not refused:
    # resume is the pause's only exit, and a deploy (the other way to
    # replace them) is refused while the project is paused.
    try:
        stale = stale_containers(paths, project_name, component="resume",
                                 compose_files=compose_files)
        recreate = stale is not None
        checked = check_start(paths, project_name, component="resume",
                              compose_files=compose_files, deploying=recreate)
    except ComposeRefused as e:
        # Exit code 3 reserved for compose hardening rejections (audit H-N2).
        print(f"ERROR: {e} {_deploy_hint(project_name, paths)}", file=sys.stderr)
        return 3, None
    except DockerError as e:
        print(f"ERROR: cannot inspect the project's containers: {e}", file=sys.stderr)
        log_error("resume", f"Container inspection failed: {e}", paths, project=project_name)
        return 1, None
    if recreate:
        print(f"  Its containers were made before the current mount rules: {stale}")
        print("  Recreating them from the deployed files instead of starting them again.")
        log_warning("resume", f"Recreating containers made before the mount rules: {stale}",
                    paths, project=project_name)

    # Pull images (unless overridden or no image: services).
    try:
        pull_image_services = {} if skip_security_checks else _services_to_pull(
            project_name, paths)
    except InventoryError as e:
        print(f"ERROR: cannot read the project's services: {e}", file=sys.stderr)
        log_error("resume", f"Inventory failed: {e}", paths, project=project_name)
        return 1, None
    if pull_image_services:
        print("  Pulling latest images...")
        try:
            before = image_ids(pull_image_services)
            compose_pull(project_dir, compose_files=compose_files,
                         project_name=project_name, services=sorted(pull_image_services))
            held = guard_pull(paths, project_name, pull_image_services, before,
                              component="resume")
            for svc, why in held.items():
                print(f"  WARNING: {svc} resumes on its previous image: the new one's "
                      f"{why}; {redeploy_command(paths, project_name)} decides from it.")
        except RunAsError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            log_error("resume", str(e), paths, project=project_name)
            return 1, None
        except DockerError as e:
            print(f"ERROR: Image pull failed: {e}", file=sys.stderr)
            print("       Use --skip-security-checks to resume without "
                  "pulling (accepts vulnerability risk).",
                  file=sys.stderr)
            log_error("resume", f"Image pull failed: {e}", paths,
                      project=project_name)
            return 1, None

    # Start containers, then give back the restart policies the pause held:
    # until the start has run they stay held, so nothing a failed start
    # leaves behind comes back on a Docker restart.
    print("  Starting containers...")
    try:
        compose_up_checked(paths, project_name, component="resume",
                           compose_files=compose_files, deploying=recreate,
                           force_recreate=recreate, earlier=checked)
    except DockerError as e:
        print(f"ERROR: compose up failed: {e}", file=sys.stderr)
        log_error("resume", f"compose up failed: {e}", paths,
                  project=project_name)
        if isinstance(e, ComposeUpFailed):
            _stop_again(project_name, paths)
        print(f"  {_deploy_hint(project_name, paths)}", file=sys.stderr)
        return 1, None
    try:
        release_restart_policies(project_name, paths)
    except DockerError as e:
        print(f"ERROR: {project_name} runs, but its containers' restart policies could not "
              f"be given back ({e}): a Docker restart will not restart them. Deploy it "
              f"again, or set them with `docker update --restart`.", file=sys.stderr)
        log_error("resume", f"Restart policies not given back: {e}", paths,
                  project=project_name)

    # Restore Caddy site config from manifest (regenerated).
    print("  Restoring Caddy routing...")
    try:
        prepare_caddy_config(paths, manifest)
        caddy_reload(paths.caddy, paths.state)
    except (DockerError, OSError) as e:
        print(f"ERROR: Caddy restore failed: {e}", file=sys.stderr)
        log_error("resume", f"Caddy restore failed: {e}", paths,
                  project=project_name)
        return 1, None

    # Smoke test.
    print("  Running smoke test...")
    smoke_ok, smoke_msg = run_smoke(project_name, paths)
    if not smoke_ok:
        # Smoke failed. Leave project up, alert, log, but proceed.
        print(f"  WARN: Smoke test failed: {smoke_msg}")
        log_warning("resume", f"Smoke failed after resume: {smoke_msg}",
                    paths, project=project_name)

    # Clear paused state (regardless of smoke outcome — project is
    # no longer paused, just possibly unhealthy).
    clear_paused_state(project_name, paths)

    # Bump last_started_at so the health-check grace window kicks in.
    # The 1-second race between resume completion and the container
    # becoming responsive used to surface as a transient FAILING status.
    from datetime import datetime, timezone
    deploy_state_path = paths.project_deploy_state(project_name)
    deploy_state = read_state(deploy_state_path)
    deploy_state["last_started_at"] = datetime.now(timezone.utc).isoformat()
    write_state(deploy_state_path, deploy_state)

    log_operation("resume", "Project resumed", paths,
                  project=project_name,
                  detail={"smoke_ok": smoke_ok, "smoke_msg": smoke_msg})

    print(f"Project '{project_name}' resumed.")
    suffix = f" — {smoke_msg}" if not smoke_ok else ""
    print(f"  Smoke: {'PASS' if smoke_ok else 'FAIL'}{suffix}")
    return 0, (None if smoke_ok else smoke_msg)


def _deploy_hint(project_name: str, paths: BoxPaths) -> str:
    """For a refusal whose remedy is a deploy, which a pause refuses."""
    return (f"It stays paused. If only a deploy can fix this: `boxmunge resume "
            f"{project_name} --no-start`, then `boxmunge "
            f"{redeploy_command(paths, project_name)}` (or `boxmunge prod-deploy "
            f"{project_name}` of an upload).")


def _stop_again(project_name: str, paths: BoxPaths) -> None:
    """The up failed part-way: what it started is stopped again, held, as
    the pause left it (pause.stop_again). If that fails, the pause is marked
    incomplete for `pause` to finish."""
    try:
        stop_again(project_name, paths)
    except DockerError as e:
        mark_pause_incomplete(project_name, paths)
        print(f"ERROR: stopping what the failed start started, or holding its restart "
              f"policies, failed: {e}. It may be running behind its maintenance page; run "
              f"`boxmunge pause {project_name}` to finish the pause.", file=sys.stderr)
        log_error("resume", f"Not stopped again after a failed start: {e}", paths,
                  project=project_name)
        return
    print(f"  What the failed start started was stopped again; {project_name} stays paused.",
          file=sys.stderr)


def hand_to_deploy_locked(project_name: str, paths: BoxPaths) -> int:
    """`resume --no-start`: start nothing, and hand the pause to the next
    deploy (pause.awaiting_deploy, commands/deploy_handover). For a project
    resume cannot start and only a deploy can repair. It stays paused for
    everything else until that deploy starts it. A quarantined project's
    deploy is scanned first (quarantine_gate). Caller holds the lock."""
    if refuse_if_legacy_stage(paths, project_name):
        return 1
    block = is_blocked(project_name, paths)
    if block is not None and block.reason is BlockReason.MIGRATING:
        print(f"ERROR: {block.refuse_message}", file=sys.stderr)
        return 1
    if not is_paused(project_name, paths):
        print(f"ERROR: Project '{project_name}' is not paused.", file=sys.stderr)
        return 1
    install = open_install_reason(paths, project_name)
    # An unfinished pause is finished by pausing again, which an open install
    # refuses: then only its install's deploy can end it.
    if pause_incomplete(project_name, paths) and install is None:
        print(f"ERROR: Pausing '{project_name}' did not finish, so it may still be serving. "
              f"Run `boxmunge pause {project_name}` to finish it first, or `boxmunge resume "
              f"{project_name}`.", file=sys.stderr)
        return 1
    if not awaiting_deploy(project_name, paths):
        mark_awaiting_deploy(project_name, paths)
        log_operation("resume", "Pause handed to the next deploy (--no-start)", paths,
                      project=project_name)
    scanned = (" (its images are scanned first; a clean deploy also lifts the CVE "
               "quarantine)" if is_quarantined(project_name, paths) else "")
    then = (f"Finish its open install{scanned}: {install}" if install is not None else
            f"Deploy it: `boxmunge {redeploy_command(paths, project_name)}`, "
            f"`boxmunge prod-deploy {project_name}` of an upload, or `promote "
            f"{project_name}`{scanned}")
    print(f"'{project_name}' was not started. It stays down behind its maintenance page, "
          f"with its containers stopped, until the next deploy (or rollback) starts it, "
          f"which ends the pause. {then}.")
    return 0


def _alert_smoke_failed(project_name: str, paths: BoxPaths, smoke_msg: str) -> None:
    notify(
        paths, "boxmunge resume: smoke failed",
        f"{project_name} resumed but smoke test failed: {smoke_msg}",
        component="resume", project=project_name,
    )


def cmd_resume(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name, usage_error
    parsed = parse_args(
        "resume", args, flags={"--yes", "--skip-security-checks", "--no-start"},
        min_positional=1, max_positional=1,
    )
    project = require_project_name("resume", parsed.positional[0])
    yes = parsed.has("--yes")
    skip_security_checks = parsed.has("--skip-security-checks")

    paths = BoxPaths()
    if parsed.has("--no-start") and skip_security_checks:
        usage_error("resume", "--no-start starts nothing, so it takes no --skip-security-checks")
    sys.exit(run_resume(project, paths, yes=yes,
                        skip_security_checks=skip_security_checks,
                        no_start=parsed.has("--no-start")))
