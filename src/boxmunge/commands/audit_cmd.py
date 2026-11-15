# SPDX-License-Identifier: Apache-2.0
"""Root's audit log commands: _audit-seal (install runs it; also the fix a
missing or unsealed log names) and _audit-rotate (the monthly timer).
Neither is in the deploy shell: only root can set the append-only attribute."""
from __future__ import annotations

import sys
from datetime import datetime, timezone

from boxmunge.api.audit_rotate import rotate
from boxmunge.api.audit_seal import SealError, read_unsupported, seal
from boxmunge.fs_nofollow import running_as_root
from boxmunge.log import log_error, log_operation, log_warning
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths

COMPONENT = "audit"


def _require_root(command: str) -> None:
    if not running_as_root():
        print(f"ERROR: {command} sets the audit log's append-only attribute, which only "
              f"root can do. Run: sudo boxmunge-server {command}", file=sys.stderr)
        sys.exit(1)


def cmd_audit_seal(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args
    parse_args("_audit-seal", args)
    _require_root("_audit-seal")
    paths = BoxPaths()
    try:
        skipped = seal(paths)
        reason = read_unsupported(paths)
    except SealError as e:
        log_error(COMPONENT, f"audit log not sealed: {e}. Fix: {e.fix}", paths)
        print(f"ERROR: the audit log was not sealed: {e}. Fix: {e.fix}", file=sys.stderr)
        sys.exit(1)
    if skipped:
        _warn_skipped(paths, skipped)
    if reason is None:
        log_operation(COMPONENT, f"sealed {paths.audit_log} append-only", paths)
        print(f"Audit log sealed: {paths.audit_log} (deploy's, 0640, append-only)")
        return
    message = (f"this host cannot set the append-only attribute on {paths.audit_log} "
               f"({reason}), so deploy can rewrite the audit log on this host. Recorded in "
               f"{paths.audit_append_unsupported}; `health` warns (audit-log)")
    log_warning(COMPONENT, message, paths)
    print(f"WARNING: {message}", file=sys.stderr)


def _warn_skipped(paths: BoxPaths, skipped: list[str]) -> None:
    """Names of an audit archive's form that are not archives: logged and
    alerted, in one alert, and left alone."""
    message = (f"{len(skipped)} name(s) in {paths.logs} look like audit log archives but are "
               f"not plain files, so they were not sealed and were left alone: "
               + "; ".join(skipped))
    log_warning(COMPONENT, message, paths)
    notify(paths, "boxmunge: unexpected audit archive", message, component=COMPONENT,
           priority=1)
    print(f"WARNING: {message}", file=sys.stderr)


def cmd_audit_rotate(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args
    parse_args("_audit-rotate", args)
    _require_root("_audit-rotate")
    paths = BoxPaths()
    try:
        archive = rotate(paths, datetime.now(timezone.utc).date())
    except SealError as e:
        message = f"{e}. Fix: {e.fix}, then check with: boxmunge health"
        log_error(COMPONENT, message, paths)
        notify(paths, "Audit log rotation failed", message, component=COMPONENT, priority=1)
        print(f"ERROR: {message}", file=sys.stderr)
        sys.exit(1)
    done = f"rotated the audit log to {archive}" if archive else "audit log empty: not rotated"
    log_operation(COMPONENT, done, paths)
    print(done)
