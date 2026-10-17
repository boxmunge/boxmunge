# SPDX-License-Identifier: Apache-2.0
"""run_as_deploy leaves nothing running once it gives up on a command."""
import os
import subprocess
import time
from pathlib import Path

import pytest

from boxmunge.as_deploy import run_as_deploy


def test_a_timeout_kills_everything_the_command_started(tmp_path: Path) -> None:
    with pytest.raises(subprocess.TimeoutExpired):
        run_as_deploy(["sh", "-c", "sleep 300 & echo $! > child.pid; wait"], tmp_path,
                      supplementary_groups=False, timeout=1)
    child = int((tmp_path / "child.pid").read_text())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    pytest.fail(f"the command's child {child} outlived its timeout")


def test_check_false_returns_a_failing_result(tmp_path: Path) -> None:
    result = run_as_deploy(["sh", "-c", "echo out; echo err >&2; exit 3"], tmp_path,
                           supplementary_groups=False, check=False)
    assert (result.returncode, result.stdout, result.stderr) == (3, "out\n", "err\n")
