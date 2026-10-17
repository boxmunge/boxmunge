# SPDX-License-Identifier: Apache-2.0
"""The upgrade's summary alerts: one per upgrade and kind, naming every
project an upgrade step left alone."""
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

    One summary rather than one alert per project; the dry run never
    alerts, so an upgrade alerts once, and again on a later upgrade only
    while the compose.yml is still refused.
    """
    if not refused:
        return
    from boxmunge.notify import notify
    lines = "\n".join(f"- {name}: {why}" for name, why in sorted(refused.items()))
    notify(paths, "upgrade — compose refused",
           f"The upgrade's compose validator refused {len(refused)} project(s). "
           f"They keep their previous configs and running containers and were "
           f"not restarted. Fix compose.yml and redeploy:\n{lines}",
           component="upgrade", priority=1)
