# SPDX-License-Identifier: Apache-2.0
"""The setup upload's destination parses to the right host in the real scp.

scp splits host from path at the first colon, so a literal IPv6 target must
be bracketed. The real scp runs with a fake ssh (-S) that records the
arguments scp passes it and exits, so nothing connects anywhere.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from boxmunge_cli.server_setup.remote import Target


def _ssh_args_from_scp(tmp_path: Path, host: str) -> list[str]:
    scp = shutil.which("scp")
    assert scp, "scp (OpenSSH client) is required for this test"
    source = tmp_path / "installer"
    source.write_text("installer")
    record = tmp_path / "ssh-args"
    fake_ssh = tmp_path / "fake-ssh"
    fake_ssh.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{record}"\nexit 1\n')
    fake_ssh.chmod(0o700)
    argv = Target("root", host, 22, tmp_path / "known_hosts").scp(str(source), "/tmp/installer")
    assert argv[0] == "scp"
    subprocess.run([scp, "-S", str(fake_ssh), *argv[1:]], capture_output=True, check=False)
    return record.read_text().splitlines()


@pytest.mark.parametrize("host", ["2001:db8::1", "203.0.113.5", "box.example.com"])
def test_scp_connects_to_the_whole_host(tmp_path: Path, host: str) -> None:
    args = _ssh_args_from_scp(tmp_path, host)
    assert args[args.index("--") + 1] == host, args
    assert args[args.index("-l") + 1] == "root", args
