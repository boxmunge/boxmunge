# SPDX-License-Identifier: Apache-2.0
"""The root install command is built from argv lists, so no value can escape.

These build the real remote command strings and parse them back the way the
server's shell will.
"""

import hashlib
import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from boxmunge_cli.server_setup.args import parse_args
from boxmunge_cli.server_setup.command import _run_install
from boxmunge_cli.server_setup.install import _RUN_VERIFIED
from boxmunge_cli.server_setup.preflight import check_freshness
from boxmunge_cli.server_setup.release import VerifiedInstaller
from boxmunge_cli.server_setup.remote import Target

WORKDIR = "/tmp/boxmunge-setup.AbC123xy"
HOSTILE_KEY = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl "
               "jane's key; $(touch /tmp/pwned) `id`")


def _installer(tmp_path: Path) -> VerifiedInstaller:
    path = tmp_path / "boxmunge-install.sh"
    path.write_bytes(b"installer")
    return VerifiedInstaller("v0.11.0", path, hashlib.sha256(b"installer").hexdigest())


@pytest.mark.parametrize("sudo", [False, True])
def test_install_command_round_trips_hostile_values(tmp_path: Path, fake_remote,
                                                    sudo: bool) -> None:
    fake_remote.respond("ssh", "mktemp -d", stdout=WORKDIR + "\n")
    target = Target("admin", "203.0.113.5", 22, tmp_path / "known_hosts")
    args = parse_args(["admin@203.0.113.5", "--email", "admin@example.com",
                       "--hostname", "box.example.com", "--yes", "--no-aide"])
    installer = _installer(tmp_path)

    assert _run_install(target, sudo, args, HOSTILE_KEY, installer) == 0

    remote = fake_remote.calls("ssh")[-1][-1]
    expected = ["sh", "-c", _RUN_VERIFIED, "sh", WORKDIR, installer.sha256,
                "--hostname", "box.example.com", "--email", "admin@example.com",
                "--ssh-key", HOSTILE_KEY, "--ssh-port", "922", "--no-aide"]
    assert shlex.split(remote) == (["sudo", "-n", *expected] if sudo else expected)
    subprocess.run(["sh", "-n", "-c", remote], check=True)


@pytest.fixture
def sha256sum_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Debian has sha256sum; on macOS stand in with the equivalent shasum."""
    if shutil.which("sha256sum"):
        return
    if not shutil.which("shasum"):
        pytest.skip("neither sha256sum nor shasum available")
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    shim = shim_dir / "sha256sum"
    shim.write_text('#!/bin/sh\nexec shasum -a 256 "$@"\n')
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shim_dir}{os.pathsep}{os.environ['PATH']}")


@pytest.mark.usefixtures("sha256sum_on_path")
def test_install_script_passes_arguments_through_verbatim(tmp_path: Path) -> None:
    # Run the real remote script locally, with a stand-in installer that
    # prints its arguments, to prove values arrive as single arguments.
    work = tmp_path / "boxmunge-setup.x"
    work.mkdir()
    (work / "boxmunge-install.sh").write_text('for a in "$@"; do printf "[%s]\\n" "$a"; done\n')
    digest = hashlib.sha256((work / "boxmunge-install.sh").read_bytes()).hexdigest()
    out = subprocess.run(["sh", "-c", _RUN_VERIFIED, "sh", str(work), digest,
                          "--ssh-key", HOSTILE_KEY],
                         capture_output=True, text=True, check=True).stdout
    assert out == f"[--ssh-key]\n[{HOSTILE_KEY}]\n"
    assert not work.exists()


@pytest.mark.usefixtures("sha256sum_on_path")
def test_tampered_upload_never_runs(tmp_path: Path) -> None:
    work = tmp_path / "boxmunge-setup.x"
    work.mkdir()
    (work / "boxmunge-install.sh").write_text("touch ran\n")
    result = subprocess.run(["sh", "-c", _RUN_VERIFIED, "sh", str(work), "0" * 64],
                            capture_output=True, text=True, cwd=tmp_path)
    assert result.returncode == 1
    assert "does not match" in result.stderr
    assert not (tmp_path / "ran").exists()


def test_preflight_passes_the_user_as_an_argument(tmp_path: Path, fake_remote) -> None:
    target = Target("deploy-1", "box.example.com", 22, tmp_path / "known_hosts")
    check_freshness(target, True)
    for argv in fake_remote.calls("ssh"):
        words = shlex.split(argv[-1])
        assert words[:2] == ["sudo", "-n"]
        if "/etc/passwd" in argv[-1] or "/var/www" in argv[-1]:
            assert words[-1] == "deploy-1"
            assert "deploy-1" not in words[4]  # the script text itself


@pytest.mark.parametrize("argv", [
    ["root@box.example.com", "--email", "me@example.com; touch /tmp/pwned"],
    ["root@box.example.com", "--email", "me@example.com", "--hostname", "a.com {\n respond hi }"],
    ["root@box.example.com", "--email", "me@example.com", "--hostname", "Box.Example.com"],
    ["ro'ot@box.example.com", "--email", "me@example.com"],
    ["root@-oProxyCommand=id", "--email", "me@example.com"],
    ["root@box.example.com;id", "--email", "me@example.com"],
    ["root@203.0.113.5", "--email", "me@example.com", "--hostname", "single-label"],
])
def test_hostile_values_are_rejected_up_front(argv: list[str], fake_remote) -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(argv)
    assert exc.value.code == 2
    assert fake_remote.calls() == []


def test_single_label_hostname_is_allowed_for_self_signed_test_setups() -> None:
    args = parse_args(["test@localhost", "--email", "test@example.com",
                       "--hostname", "boxmunge-test", "--self-signed-tls"])
    assert args.hostname == "boxmunge-test"
