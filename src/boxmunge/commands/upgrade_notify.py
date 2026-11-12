# SPDX-License-Identifier: Apache-2.0
"""The upgrade's summary alerts: one per upgrade and kind, naming every
project an upgrade step left alone, or that made the dry run refuse it."""
from __future__ import annotations

from boxmunge.paths import BoxPaths


def notify_locked_skips(paths: BoxPaths, skipped_locked: list[str]) -> None:
    """Send a Pushover summary when restart_projects skipped any projects.

    The lock-skip is logged but, in non-interactive contexts (cron timer,
    auto-update path), the operator never sees the warning. This raises
    the visibility to the same channel as other upgrade-time alerts;
    ``notify`` logs a non-delivery.
    """
    if not skipped_locked:
        return
    from boxmunge.notify import notify
    names = ", ".join(skipped_locked)
    notify(paths, "upgrade — projects skipped restart",
           f"Upgrade applied but {len(skipped_locked)} project(s) skipped "
           f"restart (locked): {names}. They will pick up new config on next "
           f"deploy.", component="upgrade")


def notify_refused(paths: BoxPaths, refused: dict[str, str]) -> None:
    """One priority-1 alert per upgrade naming every refused project.

    One summary rather than one alert per project (refused by the compose
    validator or the start checks, or a stopped project whose overlay could
    not be regenerated); the dry run never sends this one, so an upgrade
    alerts once, and again on a later upgrade only while the cause remains.
    """
    if not refused:
        return
    from boxmunge.notify import notify
    lines = "\n".join(f"- {name}: {why}" for name, why in sorted(refused.items()))
    notify(paths, "upgrade — projects refused",
           f"The upgrade refused {len(refused)} project(s). They keep their "
           f"previous configs and containers and were not restarted. Fix the "
           f"cause each line names and redeploy:\n{lines}",
           component="upgrade", priority=1)


def notify_unresolved_stages(paths: BoxPaths, semver: str, refusal: str) -> None:
    """The priority-1 alert of a dry run that refused the upgrade to
    `semver` for an unresolved stage (boxmunge.unresolved_stage), and the
    log entry Pushover's cut of a long alert points at.

    The one dry-run failure that alerts: the shims of 0.11.0 to 0.11.6 run
    the dry run and send nothing when it fails, and deploy can plant what
    refuses it, so every later release would be refused with nobody told.
    Not throttled: the shim blocklists a release whose dry run failed, so
    auto-update tries it again only after someone removes that entry, and
    a retry that is refused should say so.
    """
    from boxmunge.log import log_error
    from boxmunge.notify import notify
    notify(paths, f"upgrade to {semver} refused — unresolved stage",
           f"The upgrade to boxmunge {semver} was refused before it changed anything.\n"
           f"{refusal}", component="upgrade", priority=1)
    log_error("upgrade", f"Upgrade to {semver} refused: {refusal}", paths)
