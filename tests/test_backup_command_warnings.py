# SPDX-License-Identifier: Apache-2.0
"""Postgres backup commands that restore without replacing data are warned about."""

import pytest

from boxmunge.backup_command_warnings import backup_command_warnings
from boxmunge.manifest import validate_manifest

GOOD_DUMP = "pg_dump --clean --if-exists -U app appdb"
GOOD_RESTORE = "psql -v ON_ERROR_STOP=1 --single-transaction -U app appdb"


def _backup(dump: str, restore: str) -> dict:
    return {"type": "postgres", "service": "db", "dump_command": dump, "restore_command": restore}


def test_documented_commands_do_not_warn() -> None:
    assert backup_command_warnings(_backup(GOOD_DUMP, GOOD_RESTORE)) == []


def test_plain_pg_dump_warns_naming_the_flags() -> None:
    (w,) = backup_command_warnings(_backup("pg_dump -U app appdb", GOOD_RESTORE))
    assert "dump_command" in w and "--clean --if-exists" in w


def test_plain_psql_warns_naming_the_flags() -> None:
    (w,) = backup_command_warnings(_backup(GOOD_DUMP, "psql -U app appdb"))
    assert "restore_command" in w and "ON_ERROR_STOP=1" in w and "--single-transaction" in w


def test_both_plain_commands_warn_twice() -> None:
    assert len(backup_command_warnings(_backup("pg_dump app", "psql app"))) == 2


def test_short_clean_flag_is_accepted() -> None:
    assert backup_command_warnings(_backup("pg_dump -c --if-exists app", GOOD_RESTORE)) == []


def test_credentials_beginning_with_c_are_not_mistaken_for_clean() -> None:
    assert len(backup_command_warnings(_backup("pg_dump -Ucanary canarydb", GOOD_RESTORE))) == 1


def test_wrapper_scripts_are_not_inspected() -> None:
    assert backup_command_warnings(_backup("boxmunge-scripts/backup.sh", "boxmunge-scripts/restore.sh")) == []


@pytest.mark.parametrize("dump,restore", [
    ("cat /data/checks.db", "cat > /data/checks.db"),
    ("mysqldump -u app appdb", "mysql -u app appdb"),
])
def test_other_database_commands_do_not_warn(dump: str, restore: str) -> None:
    assert backup_command_warnings({"type": "custom", "dump_command": dump, "restore_command": restore}) == []


def test_validate_manifest_surfaces_the_warnings() -> None:
    manifest = {
        "schema_version": 2, "id": "01JABCDEFGHJKMNPQRSTVWXYZ0", "project": "myapp",
        "hosts": ["myapp.example.com"],
        "services": {"db": {"port": 5432, "internal": True, "limits": {"memory": "256m"}}},
        "backup": _backup("pg_dump app", "psql app"),
    }
    _, warnings = validate_manifest(manifest, "myapp")
    assert any("--clean" in w for w in warnings)
    assert any("ON_ERROR_STOP" in w for w in warnings)
