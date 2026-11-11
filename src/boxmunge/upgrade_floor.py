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

import re
from typing import TYPE_CHECKING

from boxmunge.version import get_build_version, parse_version_string

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

UPGRADE_FLOOR = "0.11.0"
# The last release that installs over a box below the floor.
BRIDGE_RELEASE = "0.11.6"
SHIM = "sudo /opt/boxmunge/bin/boxmunge-upgrade"
BRIDGE_COMMAND = f"{SHIM} target {BRIDGE_RELEASE}"

# What config/version may hold: one line, a version as the shim's SEMVER_RE
# reads it (scripts/boxmunge-upgrade.d/state.sh) and the +build a release
# appends. bootstrap/upgrade-floor.sh accepts exactly the same records.
RECORD_RE = re.compile(
    rb"(?P<release>(?P<core>[0-9]+\.[0-9]+\.[0-9]+)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)"
    rb"(?:\+[0-9A-Za-z.-]+)?\n?")

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


def _numbers(core: str) -> tuple[int, ...]:
    return tuple(int(number) for number in core.split("."))


def require_upgrade_floor(paths: BoxPaths, new_version: str) -> None:
    """Raise BelowUpgradeFloor unless the box records a release at or above
    the floor (pre-release and build are not compared). A missing or
    unreadable record is refused too: guessing would run this release's
    upgrade over state it may no longer understand."""
    record = paths.version_file
    raw = record.read_bytes() if record.exists() else None
    held = RECORD_RE.fullmatch(raw) if raw is not None else None
    new, _ = parse_version_string(new_version)
    if held is None:
        found = ("it is missing" if raw is None
                 else f"it holds {raw[:80].decode(errors='backslashreplace')!r}")
        raise BelowUpgradeFloor(
            f"{record} does not record the release this box runs as one line like "
            f"{BRIDGE_RELEASE} ({found}), and {STARTS_FROM}. Write that release into "
            f"the file as X.Y.Z alone: `/opt/boxmunge/env-active/bin/boxmunge-server "
            f"--version` prints it after the word boxmunge (for `boxmunge "
            f"{BRIDGE_RELEASE}+abc1234`, write {BRIDGE_RELEASE}). Then clear the "
            f"blocklist entry this refusal leaves, and upgrade again: "
            f"{SHIM} clear-blocklist {new}")
    if _numbers(held["core"].decode()) >= _numbers(UPGRADE_FLOOR):
        return
    installed = held["release"].decode()
    raise BelowUpgradeFloor(
        f"boxmunge {new} cannot be installed over {installed}: {FLOOR_RULE}\n"
        f"  This box stays on {installed}. {_after_the_bridge(new)}")
