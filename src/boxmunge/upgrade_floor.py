# SPDX-License-Identifier: Apache-2.0
"""The upgrade floor: the oldest installed release an upgrade may start from.

Raising the floor is what lets code for older sources be deleted, so a
release must refuse to be installed over anything below it. The refusal runs
in the pre-flight (`upgrade --dry-run`): every shim since 0.5.8 runs that
before it stashes, replaces itself or runs install.sh, so a refused box is
left exactly as it was, still able to install the bridge release.

Shims of 0.5.8 to 0.9.1 never reach the dry run. Their pre-flight first
reads `boxmunge.__version__`, which fails with package_version_refusal().
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from boxmunge.release_selection import VERSION_RE, version_tuple
from boxmunge.version import get_build_version, parse_version_string

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

UPGRADE_FLOOR = "0.11.0"
# The last release that installs over a box below the floor.
BRIDGE_RELEASE = "0.11.6"
SHIM = "sudo /opt/boxmunge/bin/boxmunge-upgrade"
BRIDGE_COMMAND = f"{SHIM} target {BRIDGE_RELEASE}"

STARTS_FROM = f"an upgrade must start from {UPGRADE_FLOOR} or later"
FLOOR_RULE = f"{STARTS_FROM}. Upgrade to {BRIDGE_RELEASE} first: {BRIDGE_COMMAND}"


class BelowUpgradeFloor(Exception):
    """This release must not be installed over the release the box runs."""


def _after_the_bridge(new: str) -> str:
    """Every shim blocklists a release whose pre-flight failed."""
    return (f"The upgrader blocklists {new} on this box after this refusal; that "
            f"does not stop the upgrade to {BRIDGE_RELEASE}. Once the box runs "
            f"{BRIDGE_RELEASE}, clear it before upgrading further: "
            f"{SHIM} clear-blocklist {new}")


def package_version_refusal() -> str:
    """What reading `boxmunge.__version__` fails with."""
    new, _ = parse_version_string(get_build_version())
    return (f"module 'boxmunge' has no attribute '__version__'. Only the upgrader "
            f"of a release before 0.9.2 reads it, and boxmunge {new} cannot be "
            f"installed over one: {FLOOR_RULE}\n  {_after_the_bridge(new)}")


def require_upgrade_floor(paths: BoxPaths, new_version: str) -> None:
    """Raise BelowUpgradeFloor unless the box records a release at or above
    the floor. A missing or unreadable record is refused too: guessing would
    run this release's upgrade over state it may no longer understand."""
    record = paths.version_file
    recorded = record.read_text().strip() if record.exists() else ""
    installed, _ = parse_version_string(recorded)
    new, _ = parse_version_string(new_version)
    if not recorded or not VERSION_RE.match(installed):
        found = f"it holds {recorded!r}" if recorded else "it is missing or empty"
        raise BelowUpgradeFloor(
            f"{record} does not record the release this box runs ({found}), and "
            f"{STARTS_FROM}. Write the release that "
            f"`/opt/boxmunge/env-active/bin/boxmunge-server --version` prints into "
            f"that file. Then clear the blocklist entry this refusal leaves, and "
            f"upgrade again: {SHIM} clear-blocklist {new}")
    if version_tuple(installed) >= version_tuple(UPGRADE_FLOOR):
        return
    raise BelowUpgradeFloor(
        f"boxmunge {new} cannot be installed over {installed}: {FLOOR_RULE}\n"
        f"  This box stays on {installed}. {_after_the_bridge(new)}")
