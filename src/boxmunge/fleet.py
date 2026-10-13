# SPDX-License-Identifier: Apache-2.0
"""Per-project failure isolation for commands that loop over every project.

A fleet loop (check-all, status, health, ...) must not let one project's
broken input stop it from reaching the others, and must not let that
project silently vanish either. Catch ``PROJECT_INPUT_ERRORS`` around the
per-project body, call ``report_project_failure``, carry on, and make the
command's exit code show that a project failed.
"""

import json
import sys

from boxmunge.config import ConfigError
from boxmunge.cve.quarantine import QuarantineError
from boxmunge.log import log_error
from boxmunge.manifest import ManifestError
from boxmunge.paths import BoxPaths, InvalidProjectName
from boxmunge.state import StateError

# Errors raised by unreadable per-project inputs: manifest, host config,
# JSON state files (health, deploy, quarantine, pause), and a project
# directory whose name is no longer valid (a reserved name). Programming
# errors are deliberately not in this list; they still propagate.
PROJECT_INPUT_ERRORS: tuple[type[Exception], ...] = (
    InvalidProjectName,
    ManifestError,
    ConfigError,
    StateError,
    QuarantineError,
    json.JSONDecodeError,
    OSError,
)


def report_project_failure(
    component: str, project: str, error: Exception, paths: BoxPaths,
) -> None:
    """Report one project's failure on stderr and in the operational log."""
    print(f"ERROR: {component}: {project}: {error}", file=sys.stderr)
    log_error(
        component, f"project could not be processed: {error}",
        paths, project=project,
        detail={"error_type": type(error).__name__},
    )
