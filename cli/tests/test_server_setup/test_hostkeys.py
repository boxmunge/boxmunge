# SPDX-License-Identifier: Apache-2.0
"""Host-key verification for server-setup."""

import hashlib
import subprocess
from pathlib import Path

import pytest

from boxmunge_cli.server_setup import command
from boxmunge_cli.server_setup.args import parse_args
from boxmunge_cli.server_setup.hostkeys import (
    HostKeyError,
    ensure_trusted,
    fingerprint,
    record_for_port,
)
from boxmunge_cli.server_setup.release import VerifiedInstaller
from boxmunge_cli.server_setup.remote import Target

HOST = "box.example.com"


def _keygen(tmp_path: Path, name: str, key_type: str = "ed25519") -> tuple[str, str, str]:
    path = tmp_path / name
    subprocess.run(["ssh-keygen", "-q", "-t", key_type, "-N", "", "-f", str(path)], check=True)
    key_type_s, b64 = Path(f"{path}.pub").read_text().split()[:2]
    fp = subprocess.run(["ssh-keygen", "-lf", str(Path(f"{path}.pub"))],
                        capture_output=True, text=True, check=True).stdout.split()[1]
    return key_type_s, b64, fp


@pytest.fixture
def keys(tmp_path: Path):
    return {"ed": _keygen(tmp_path, "host_ed.key"),
            "other": _keygen(tmp_path, "attacker.key")}


@pytest.fixture
def target(tmp_path: Path) -> Target:
    return Target("root", HOST, 22, tmp_path / "home" / ".ssh" / "known_hosts")


def _offer(fake_remote, *key_lines: tuple[str, str, str]) -> None:
    out = "".join(f"{HOST} {t} {b}\n" for t, b, _ in key_lines)
    fake_remote.respond("ssh-keyscan", HOST, stdout=out)


def test_fingerprint_matches_ssh_keygen(keys) -> None:
    key_type, b64, fp = keys["ed"]
    assert fingerprint(b64) == fp


def test_known_host_is_left_to_ssh(target: Target, keys, fake_remote) -> None:
    target.known_hosts.parent.mkdir(parents=True)
    t, b, _ = keys["ed"]
    target.known_hosts.write_text(f"{HOST} {t} {b}\n")
    ensure_trusted(target, None, None)
    assert fake_remote.calls("ssh-keyscan") == []


def test_matching_fingerprint_records_only_the_verified_key(target, keys, fake_remote) -> None:
    _offer(fake_remote, keys["other"], keys["ed"])
    ensure_trusted(target, keys["ed"][2], None)
    t, b, _ = keys["ed"]
    assert target.known_hosts.read_text() == f"{HOST} {t} {b}\n"
    assert target.known_hosts.stat().st_mode & 0o777 == 0o600


def test_mismatching_fingerprint_is_refused(target, keys, fake_remote) -> None:
    _offer(fake_remote, keys["other"])
    with pytest.raises(HostKeyError, match="does not match"):
        ensure_trusted(target, keys["ed"][2], None)
    assert not target.known_hosts.exists()


def test_new_host_without_a_way_to_confirm_is_refused(target, keys, fake_remote) -> None:
    _offer(fake_remote, keys["ed"])
    with pytest.raises(HostKeyError, match="--host-key-fingerprint"):
        ensure_trusted(target, None, None)
    assert not target.known_hosts.exists()


def test_interactive_confirmation_shows_the_fingerprint(target, keys, fake_remote,
                                                        capsys) -> None:
    _offer(fake_remote, keys["ed"])
    ensure_trusted(target, None, lambda prompt: True)
    assert keys["ed"][2] in capsys.readouterr().out
    assert target.known_hosts.read_text().startswith(f"{HOST} ssh-ed25519 ")


def test_declined_confirmation_records_nothing(target, keys, fake_remote) -> None:
    _offer(fake_remote, keys["ed"])
    with pytest.raises(HostKeyError, match="not trusted"):
        ensure_trusted(target, None, lambda prompt: False)
    assert not target.known_hosts.exists()


def test_verified_key_is_recorded_for_the_new_port(target, keys, fake_remote) -> None:
    _offer(fake_remote, keys["ed"])
    ensure_trusted(target, keys["ed"][2], None)
    record_for_port(target, 922)
    t, b, _ = keys["ed"]
    assert f"[{HOST}]:922 {t} {b}\n" in target.known_hosts.read_text()


def test_every_setup_connection_checks_host_keys(target) -> None:
    for argv in (target.ssh("true"), target.ssh("true", True), target.scp("a", "/tmp/b")):
        assert "StrictHostKeyChecking=yes" in argv
        assert f"UserKnownHostsFile={target.known_hosts}" in argv
        assert not any("/dev/null" in a or "accept-new" in a for a in argv)


def _installer(tmp_path: Path) -> VerifiedInstaller:
    path = tmp_path / "boxmunge-install.sh"
    path.write_bytes(b"installer")
    return VerifiedInstaller("v0.11.0", path, hashlib.sha256(b"installer").hexdigest())


def _healthy_debian(fake_remote) -> None:
    fake_remote.respond("ssh", "echo ok", stdout="ok\n")
    fake_remote.respond("ssh", "cat /etc/os-release", stdout='ID=debian\nVERSION_ID="13"\n')
    fake_remote.respond("ssh", "uname -m", stdout="x86_64\n")
    fake_remote.respond("ssh", "test -f /opt/boxmunge", rc=1)
    fake_remote.respond("ssh", "id -u", stdout="0\n")
    fake_remote.respond("ssh", "test -d /opt/boxmunge", rc=1)
    fake_remote.respond("ssh", "mktemp -d", stdout="/tmp/boxmunge-setup.AbC123xy\n")


def test_full_setup_refuses_an_unverified_host_before_any_ssh(tmp_path, keys, fake_remote,
                                                             monkeypatch) -> None:
    _offer(fake_remote, keys["other"])
    monkeypatch.setattr(command, "fetch_verified_installer",
                        lambda tag, workdir: _installer(tmp_path))
    args = parse_args([f"root@{HOST}", "--email", "admin@example.com", "--yes",
                       "--ssh-key", keys_line(keys), "--host-key-fingerprint", keys["ed"][2]])
    rc = command.run_server_setup(args, known_hosts=tmp_path / "kh")
    assert rc == 1
    assert fake_remote.calls("ssh") == [] and fake_remote.calls("scp") == []


def test_full_setup_with_a_verified_host(tmp_path, keys, fake_remote, monkeypatch) -> None:
    _offer(fake_remote, keys["ed"])
    _healthy_debian(fake_remote)
    monkeypatch.setattr(command, "fetch_verified_installer",
                        lambda tag, workdir: _installer(tmp_path))
    args = parse_args([f"root@{HOST}", "--email", "admin@example.com", "--yes",
                       "--ssh-key", keys_line(keys), "--host-key-fingerprint", keys["ed"][2]])
    known_hosts = tmp_path / "kh"
    assert command.run_server_setup(args, known_hosts=known_hosts) == 0
    assert f"[{HOST}]:922 ssh-ed25519" in known_hosts.read_text()
    for argv in fake_remote.calls("ssh") + fake_remote.calls("scp"):
        assert "StrictHostKeyChecking=yes" in argv


def keys_line(keys) -> str:
    t, b, _ = keys["ed"]
    return f"{t} {b} me@example.com"
