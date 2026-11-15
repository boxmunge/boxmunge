# SPDX-License-Identifier: Apache-2.0
"""Internal command: _run-job <id>

Run by the job runner (boxmunge-jobs.service), one process per job. Not in
shell.ALLOWED_COMMANDS. Exits with run_job's code: 0 once the job is
terminal, 75 (EX_TEMPFAIL) when an upgrade held the jobs gate and the job
was left queued, 1 when the job is not queued.
"""
import re
import sys

from boxmunge.commands.argv import parse_args, usage_error
from boxmunge.paths import BoxPaths


def cmd_run_job(args: list[str]) -> None:
    # boxmunge.api is imported here, not at the top, so that no other
    # command loads it.
    from boxmunge.api.actions import build_registry
    from boxmunge.api.host import LiveHost
    from boxmunge.api.job_worker import run_job
    from boxmunge.api.jobs import JOB_ID_PATTERN
    parsed = parse_args("_run-job", args, min_positional=1, max_positional=1)
    job_id = parsed.positional[0]
    if not re.fullmatch(JOB_ID_PATTERN, job_id):
        usage_error("_run-job", f"{job_id!r} is not a job id (26 characters, a ULID)")
    paths = BoxPaths()
    sys.exit(run_job(paths, job_id, build_registry(), LiveHost(paths)))
