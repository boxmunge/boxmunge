# SPDX-License-Identifier: Apache-2.0
"""Internal command: _job-runner

Run by boxmunge-jobs.service (started by boxmunge-jobs.path when queue/
changes). Not in shell.ALLOWED_COMMANDS. Exits with run_runner's code.
"""
import sys

from boxmunge.commands.argv import parse_args
from boxmunge.paths import BoxPaths


def cmd_job_runner(args: list[str]) -> None:
    # boxmunge.api is imported here, not at the top, so that no other
    # command loads it.
    from boxmunge.api import job_runner
    parse_args("_job-runner", args)
    sys.exit(job_runner.run_runner(BoxPaths()))
