"""Tests for SSH public key selection and validation."""

import subprocess
from pathlib import Path

import pytest

from boxmunge_cli.server_setup.ssh_key import SSHKeyError, detect_ssh_key, parse_public_key


def _keygen(tmp_path: Path, name: str, key_type: str, comment: str = "me@example.com"):
    path = tmp_path / name
    subprocess.run(["ssh-keygen", "-q", "-t", key_type, "-N", "", "-C", comment,
                    "-f", str(path)], check=True)
    fp = subprocess.run(["ssh-keygen", "-lf", f"{path}.pub"], capture_output=True,
                        text=True, check=True).stdout.split()[1]
    return path, Path(f"{path}.pub"), fp


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    d = tmp_path_factory.mktemp("keys")
    return {"ed": _keygen(d, "id_ed25519", "ed25519", "jane's key"),
            "ecdsa": _keygen(d, "id_ecdsa", "ecdsa"),
            "rsa": _keygen(d, "id_rsa", "rsa")}


@pytest.fixture
def no_agent(monkeypatch, tmp_path):
    """An ssh-add on PATH that reports no agent, and an empty HOME."""
    bin_dir = tmp_path / "noagent"
    bin_dir.mkdir()
    (bin_dir / "ssh-add").write_text("#!/bin/sh\nexit 2\n")
    (bin_dir / "ssh-add").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return home


class TestExplicitKey:
    def test_public_key_file(self, keys) -> None:
        _, pub, fp = keys["ed"]
        key = detect_ssh_key(str(pub))
        assert key.line == pub.read_text().strip()
        assert key.fingerprint == fp
        assert key.comment == "jane's key"

    def test_private_key_file_is_refused(self, keys) -> None:
        private, _, _ = keys["ed"]
        with pytest.raises(SSHKeyError, match="PRIVATE key"):
            detect_ssh_key(str(private))

    @pytest.mark.parametrize("which", ["ed", "ecdsa", "rsa"])
    def test_inline_keys_of_every_type(self, keys, which) -> None:
        _, pub, fp = keys[which]
        assert detect_ssh_key(pub.read_text().strip()).fingerprint == fp

    def test_multiple_lines_are_refused(self, keys, tmp_path) -> None:
        both = tmp_path / "both.pub"
        both.write_text(keys["ed"][1].read_text() + keys["rsa"][1].read_text())
        with pytest.raises(SSHKeyError, match="exactly one"):
            detect_ssh_key(str(both))

    def test_mismatched_type_is_refused(self, keys) -> None:
        _, b64, comment = keys["ed"][1].read_text().split(None, 2)
        with pytest.raises(SSHKeyError, match="material"):
            parse_public_key(f"ssh-rsa {b64} {comment}", "--ssh-key")

    def test_garbage_is_refused(self) -> None:
        with pytest.raises(SSHKeyError):
            parse_public_key("ssh-ed25519 not-base64!!", "--ssh-key")

    def test_missing_file(self) -> None:
        with pytest.raises(SSHKeyError, match="not found"):
            detect_ssh_key("/nonexistent/key.pub")


class TestAutoDetect:
    def test_prefers_ed25519_from_agent(self, keys, monkeypatch, tmp_path) -> None:
        bin_dir = tmp_path / "agent"
        bin_dir.mkdir()
        listing = keys["rsa"][1].read_text() + keys["ed"][1].read_text()
        (bin_dir / "ssh-add").write_text(f"#!/bin/sh\ncat <<'EOF'\n{listing}EOF\n")
        (bin_dir / "ssh-add").chmod(0o755)
        monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
        assert detect_ssh_key(None).fingerprint == keys["ed"][2]

    def test_falls_back_to_files(self, keys, no_agent) -> None:
        (no_agent / ".ssh").mkdir()
        (no_agent / ".ssh" / "id_rsa.pub").write_text(keys["rsa"][1].read_text())
        assert detect_ssh_key(None).fingerprint == keys["rsa"][2]

    def test_raises_when_nothing_found(self, no_agent) -> None:
        with pytest.raises(SSHKeyError, match="No SSH public key found"):
            detect_ssh_key(None)
