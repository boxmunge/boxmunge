# SPDX-License-Identifier: Apache-2.0
"""Which release `upgrade-howto` and `upgrade-check` are about, and the
release this box runs.

The target is the release named with --version, or else the newest release
of any class (discovery's "latest" mode, as a plain `upgrade` uses). With
`version_check.enabled: false` nothing is asked of boxmunge.dev or GitHub,
so the release must be named: both commands refuse without --version.

A named release is X.Y.Z exactly, as upgrade-notes.json names releases. The
box itself may run a pre-release (X.Y.Z-pre, which comes before X.Y.Z);
discovery cannot compare one with releases, so such a box names the target
too.
"""
from __future__ import annotations

from boxmunge.config import ConfigError
from boxmunge.paths import BoxPaths
from boxmunge.upgrade_discovery import discover_update
from boxmunge.upgrade_floor import RECORD_RE
from boxmunge.upgrade_notes import NotesError, version_key
from boxmunge.version_check_optout import RELEASES_PAGE, version_checks_off

NAME_IT = f"pass the release: --version X.Y.Z (releases: {RELEASES_PAGE})"
OPTED_OUT = ("version checks are off on this box (version_check.enabled: false), so the "
             f"newest release cannot be looked up. Pass it: --version X.Y.Z (releases: "
             f"{RELEASES_PAGE})")


class TargetError(Exception):
    """No target release: `message` says why and what to run instead."""

    def __init__(self, exit_code: int, message: str) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.message = message


def _release(value: object, what: str, exit_code: int) -> str:
    try:
        version_key(value)
    except NotesError:
        raise TargetError(exit_code, f"{what} {value!r} is not a release X.Y.Z, like "
                                     f"0.12.0") from None
    return value  # type: ignore[return-value]


def installed_release(paths: BoxPaths) -> str:
    """The release config/version records, without its +build: X.Y.Z, or
    X.Y.Z-pre on a box that runs a pre-release."""
    record = paths.version_file
    fix = (f"The operator writes the release this box runs into {record} as root, as "
           f"X.Y.Z alone (`/opt/boxmunge/env-active/bin/boxmunge-server --version` prints "
           f"it after the word boxmunge), then run this command again")
    try:
        held = RECORD_RE.fullmatch(record.read_bytes())
    except OSError as e:
        raise TargetError(1, f"{record} cannot be read ({e.strerror or e}). {fix}") from None
    if held is None or not _is_release(held["core"].decode()):
        raise TargetError(1, f"{record} does not record a release this box runs as one "
                             f"line like 0.11.8. {fix}")
    return held["release"].decode()


def _is_release(core: str) -> bool:
    try:
        version_key(core)
    except NotesError:
        return False
    return True


def is_newer(target: str, installed: str) -> bool:
    """True if release `target` (X.Y.Z) comes after `installed`, which may be
    a pre-release: X.Y.Z-pre comes before X.Y.Z (and two pre-releases are
    never compared: a target is never one)."""
    core, _, pre = installed.partition("-")
    return (version_key(target), 1) > (version_key(core), 0 if pre else 1)


def not_newer(command: str, target: str, installed: str, *, explicit: bool) -> TargetError:
    """The refusal when `target` is not newer than the installed release."""
    if not explicit:
        return TargetError(2, f"this box runs {installed}, the newest release, so there is no "
                              f"upgrade to check; `upgrade-howto` says the same")
    return TargetError(2, f"this box already runs {installed}, which is not older than "
                          f"{target}, and `{command}` is about an upgrade to a newer release. "
                          f"Name one: --version X.Y.Z (releases: {RELEASES_PAGE}), or, with "
                          f"version checks on, run `{command}` without --version for the "
                          f"newest")


def resolve_target(paths: BoxPaths, explicit: str | None) -> str:
    """The release to prepare or check for: `explicit` (--version), or the
    newest release; the installed release when the box is up to date.
    Raises TargetError: exit 2 for a usage problem (a malformed version, or
    no version where one must be named), exit 1 when discovery failed."""
    if explicit is not None:
        return _release(explicit, "--version", 2)
    try:
        off = version_checks_off(paths)
    except ConfigError as e:
        raise TargetError(1, f"cannot read boxmunge.yml to see whether version checks are "
                             f"on ({e}), so the newest release is not looked up. Fix the "
                             f"file, or {NAME_IT}") from None
    if off:
        raise TargetError(2, OPTED_OUT)
    installed = installed_release(paths)
    if "-" in installed:
        raise TargetError(2, f"this box runs a pre-release, {installed}, which release "
                             f"discovery cannot compare with releases; {NAME_IT}")
    found = discover_update(paths, "latest")
    action = found.get("action")
    if action in ("upgrade", "blocklisted"):
        return _release(found.get("version"), "release discovery's newest release", 1)
    if action == "up_to_date":
        return installed
    if action == "error":
        raise TargetError(1, f"{found.get('message')} To name the release instead, {NAME_IT}")
    raise TargetError(1, f"release discovery gave an answer this release does not know "
                         f"({action!r}); {NAME_IT}")
