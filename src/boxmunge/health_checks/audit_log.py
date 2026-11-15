# SPDX-License-Identifier: Apache-2.0
"""Health check: is the action audit log there, a plain file, append-only?

An error, on purpose, when the log is missing (every audited call is then
refused) or has lost the append-only attribute on a host that can set it:
install sets both, so either means a platform control is off and probation
rolling an upgrade back over it is right. A host recorded as unable to set
the attribute (api.audit_seal) warns instead, so it can still upgrade.
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING

from boxmunge.api.audit_seal import SealError, is_append_only, open_log, read_unsupported
from boxmunge.commands.health_cmd import HealthCheck

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

NAME = "audit-log"
RECREATE = "recreate as root: boxmunge-server _audit-seal"
SET_AGAIN = "set it again as root: boxmunge-server _audit-seal"


def check_audit_log(paths: BoxPaths) -> HealthCheck:
    try:
        fd = open_log(paths.audit_log, create=False)
    except FileNotFoundError:
        return HealthCheck(NAME, "error", f"{paths.audit_log} is missing, so every audited "
                           f"action is refused; {RECREATE}")
    except SealError as e:
        return HealthCheck(NAME, "error", f"{e}; {RECREATE}")
    try:
        try:
            if is_append_only(fd):
                return HealthCheck(NAME, "ok", "append-only")
            unreadable = ""
        except OSError as e:
            unreadable = f" (its attributes cannot be read: {e})"
    finally:
        os.close(fd)
    try:
        reason = read_unsupported(paths)
    except SealError as e:
        return HealthCheck(NAME, "error", f"{paths.audit_log} is not append-only, and {e}")
    if reason is not None:
        return HealthCheck(NAME, "warn", f"not append-only: this host cannot set the attribute "
                           f"({reason}), so deploy can rewrite the audit log on this host")
    return HealthCheck(NAME, "error", f"{paths.audit_log} is not append-only{unreadable}; "
                       f"{SET_AGAIN}")
