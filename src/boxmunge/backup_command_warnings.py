# SPDX-License-Identifier: Apache-2.0
"""Warnings for backup commands that restore without replacing data.

A plain `pg_dump` has no DROP statements and `psql` exits 0 when statements
fail, so restoring into a database that already has the tables leaves the
current data in place and reports success. The manifest cannot be rejected
for this (a wrapper script may handle it), so it is a warning.
"""

import re
import shlex

_PSQL = re.compile(r"(?<![\w./-])psql(?![\w-])")
_PG_DUMP = re.compile(r"(?<![\w./-])pg_dump(?![\w-])")


def backup_command_warnings(backup: dict) -> list[str]:
    """Warnings for postgres dump/restore commands that would not replace data."""
    warnings: list[str] = []
    dump = backup.get("dump_command")
    restore = backup.get("restore_command")
    if isinstance(dump, str) and _PG_DUMP.search(dump) and not _has_clean(dump):
        warnings.append(
            "backup.dump_command runs pg_dump without --clean, so the dump has no "
            "DROP statements and a restore cannot replace existing tables. Add "
            "--clean --if-exists, e.g. 'pg_dump --clean --if-exists -U <user> <db>'."
        )
    if isinstance(restore, str) and _PSQL.search(restore) and "ON_ERROR_STOP" not in restore:
        warnings.append(
            "backup.restore_command runs psql without ON_ERROR_STOP, so psql exits 0 "
            "even when statements fail and a half-applied restore reports success. "
            "Add -v ON_ERROR_STOP=1 --single-transaction, e.g. "
            "'psql -v ON_ERROR_STOP=1 --single-transaction -U <user> <db>'."
        )
    return warnings


def _has_clean(command: str) -> bool:
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    return "--clean" in tokens or "-c" in tokens
