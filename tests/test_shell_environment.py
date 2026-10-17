# SPDX-License-Identifier: Apache-2.0
"""The restricted shell hands its commands none of the client's other variables."""
import os
import pwd
from unittest.mock import patch

import pytest

from boxmunge.shell import SHELL_PATH, main, restrict_environment

CLIENT = {
    "BASH_ENV": "$(touch /tmp/pwned)", "ENV": "/tmp/x", "LD_PRELOAD": "/tmp/x.so",
    "PYTHONPATH": "/tmp", "PATH": "/tmp/evil:/usr/bin", "HOME": "/tmp/evil",
    "USER": "root", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "xterm",
    "SSH_CONNECTION": "192.0.2.1 5 192.0.2.2 922", "SSH_ORIGINAL_COMMAND": "status",
}


def test_only_locale_terminal_and_ssh_variables_survive() -> None:
    env = dict(CLIENT)
    restrict_environment(env)
    account = pwd.getpwuid(os.getuid())
    assert env == {
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "xterm",
        "SSH_CONNECTION": "192.0.2.1 5 192.0.2.2 922", "SSH_ORIGINAL_COMMAND": "status",
        "PATH": SHELL_PATH, "HOME": account.pw_dir, "USER": account.pw_name,
        "LOGNAME": account.pw_name, "SHELL": account.pw_shell,
    }


@patch.dict(os.environ, CLIENT, clear=True)
@patch("boxmunge.shell.subprocess.run")
def test_commands_run_in_the_restricted_environment(mock_run) -> None:
    seen = {}
    mock_run.side_effect = lambda argv: seen.update(os.environ) or type("R", (), {"returncode": 0})
    with patch("sys.argv", ["boxmunge-shell", "-c", "status"]), pytest.raises(SystemExit):
        main()
    assert mock_run.call_args.args[0] == ["boxmunge-server", "status"]
    for name in ("BASH_ENV", "ENV", "LD_PRELOAD", "PYTHONPATH"):
        assert name not in seen
    assert seen["PATH"] == SHELL_PATH
