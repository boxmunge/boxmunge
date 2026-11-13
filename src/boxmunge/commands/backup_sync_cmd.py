# SPDX-License-Identifier: Apache-2.0
"""boxmunge backup-sync: copy the encrypted backups off-site."""

import sys
from datetime import datetime, timezone

from boxmunge.backup_alerts import deliver
from boxmunge.backup_evidence import (
    deployed_projects, record_sync_not_expected, record_sync_run, record_synced,
    reporting_unwritten,
)
from boxmunge.config import ConfigError
from boxmunge.host_config_alert import load_for_job
from boxmunge.log import log_error, log_operation
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths


def run_backup_sync(paths: BoxPaths, project_name: str | None = None) -> int:
    """Copy encrypted backups to the configured remote with rclone.

    ``rclone copy``, never ``sync``: the remote is an archive, not a mirror,
    so a local prune or ``project-delete`` never deletes an off-site copy.
    Off-site retention is the remote's job (for example a bucket lifecycle
    rule). Layout on the remote: ``<remote>/<project>/backups/<snapshot>``.

    The all-projects form is the nightly timer's: its outcome is recorded,
    and a failure alerts (backup_alerts). A one-project sync records only
    that project's copy.
    """
    with reporting_unwritten(paths, notify):
        return _sync(paths, project_name)


def _sync(paths: BoxPaths, project_name: str | None) -> int:
    try:
        config = load_for_job(paths, "backup-sync", reads=("backup_remote",))
    except ConfigError as e:
        # Nothing is recorded: no alert can be sent without the config, and
        # the snapshots keep waiting for their copy, which backup-freshness
        # and the 50-hour alert report once it can be read.
        log_error("backup-sync", f"Config error: {e}", paths)
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    remote = config.get("backup_remote", "")
    if not remote:
        if project_name is None:
            record_sync_not_expected(paths)
        print("ERROR: backup_remote not configured in boxmunge.yml", file=sys.stderr)
        return 1

    if project_name:
        src = paths.project_backups(project_name)
        dest = f"{remote}/{project_name}/backups"
        include = "/*.tar.gz.age"
    else:
        src = paths.projects
        dest = remote
        include = "/*/backups/*.tar.gz.age"

    print(f"Copying backups to {dest}...")

    from boxmunge.system_container import RCLONE_CONFIG, SystemContainerError, connect

    started = datetime.now(timezone.utc)
    try:
        tools = connect(paths)
        tools.run(["rclone", "copy", tools.path(src), dest,
                   "--include", include,
                   "--config", RCLONE_CONFIG])
    except SystemContainerError as e:
        print(f"ERROR: rclone copy failed: {e}", file=sys.stderr)
        log_error("backup", f"Backup sync to {dest} failed: {e}", paths)
        if project_name is None:
            record_sync_run(paths, f"rclone copy to {dest} failed: {e}")
            deliver(paths, notify)
        return 1

    record_synced(paths, [project_name] if project_name else deployed_projects(paths), started)
    if project_name is None:
        record_sync_run(paths, None)
        deliver(paths, notify)
    log_operation("backup", f"Backup sync to {dest} completed", paths)
    print("Backup sync complete.")
    return 0


def cmd_backup_sync(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name
    parsed = parse_args("backup-sync", args, max_positional=1)
    project = None
    if parsed.positional:
        project = require_project_name("backup-sync", parsed.positional[0])
    paths = BoxPaths()
    sys.exit(run_backup_sync(paths, project))
