# SPDX-License-Identifier: Apache-2.0
"""Named crash points for the crash-safety tests.

A test sets BOXMUNGE_TEST_CRASH_AT=<name>; the process then dies at that
point exactly as a power cut or SIGKILL would (no cleanup, exit 137).
Unset (always, in production) this does nothing.
"""
from __future__ import annotations

import os

CRASH_ENV = "BOXMUNGE_TEST_CRASH_AT"


def crash_point(name: str) -> None:
    if os.environ.get(CRASH_ENV) == name:
        os._exit(137)
