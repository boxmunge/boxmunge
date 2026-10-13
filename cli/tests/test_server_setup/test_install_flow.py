# SPDX-License-Identifier: Apache-2.0
"""The install step: what server-setup actually sends to the server."""

import hashlib
from pathlib import Path

from boxmunge_cli.server_setup.args import parse_args
from boxmunge_cli.server_setup.command import _run_install
from boxmunge_cli.server_setup.release import VerifiedInstaller

WORKDIR = "/tmp/boxmunge-setup.AbC123xy"
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@example.com"


def _installer(tmp_path: Path) -> VerifiedInstaller:
    path = tmp_path / "boxmunge-install.sh"
    path.write_bytes(b"installer")
    return VerifiedInstaller("v0.11.0", path, hashlib.sha256(b"installer").hexdigest())


def _args(*extra: str):
    return parse_args(["root@203.0.113.5", "--email", "admin@example.com",
                       "--hostname", "box.example.com", "--yes", *extra])


def test_uploads_the_verified_installer_and_rechecks_it(tmp_path: Path, fake_remote) -> None:
    fake_remote.respond("ssh", "mktemp -d", stdout=WORKDIR + "\n")
    installer = _installer(tmp_path)

    rc = _run_install("root", "203.0.113.5", 22, False, _args(), KEY, installer)

    assert rc == 0
    [scp] = fake_remote.calls("scp")
    assert scp[-2] == str(installer.path)
    assert scp[-1] == f"root@203.0.113.5:{WORKDIR}/boxmunge-install.sh"
    run = fake_remote.calls("ssh")[-1][-1]
    assert f"{installer.sha256}" in run and "sha256sum -c" in run
    assert "bash boxmunge-install.sh" in run
    assert f"rm -rf {WORKDIR}" in run
    every_call = " ".join(" ".join(c) for c in fake_remote.calls())
    assert "curl" not in every_call and "api.github.com" not in every_call
    assert "tarball_url" not in every_call


def test_refuses_an_unexpected_remote_workdir(tmp_path: Path, fake_remote, capsys) -> None:
    fake_remote.respond("ssh", "mktemp -d", stdout="/tmp/x; rm -rf /\n")
    rc = _run_install("root", "203.0.113.5", 22, False, _args(), KEY, _installer(tmp_path))
    assert rc == 1
    assert fake_remote.calls("scp") == []
    assert "temp dir" in capsys.readouterr().err


def test_failed_upload_stops_before_running(tmp_path: Path, fake_remote) -> None:
    fake_remote.respond("ssh", "mktemp -d", stdout=WORKDIR + "\n")
    fake_remote.respond("scp", "boxmunge-install.sh", rc=1)
    rc = _run_install("root", "203.0.113.5", 22, False, _args(), KEY, _installer(tmp_path))
    assert rc == 1
    assert not [c for c in fake_remote.calls("ssh") if "bash" in c[-1]]


def test_local_bundle_is_a_loud_development_path(tmp_path: Path, fake_remote, capsys) -> None:
    fake_remote.respond("ssh", "mktemp -d", stdout=WORKDIR + "\n")
    bundle = tmp_path / "boxmunge-0.11.0.tar.gz"
    bundle.write_bytes(b"x")
    args = _args("--local-bundle", str(bundle))
    rc = _run_install("root", "203.0.113.5", 22, False, args, KEY, None)
    assert rc == 0
    assert "unverified" in capsys.readouterr().err
    assert fake_remote.calls("scp")[0][-1] == f"root@203.0.113.5:{WORKDIR}/release.tar.gz"
