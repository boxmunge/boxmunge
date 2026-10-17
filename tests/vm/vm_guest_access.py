"""How the VM test reaches the guest, and how the guest reaches the internet.

Host key: the harness generates the VM's ed25519 host key itself and hands it
to cloud-init, so the key is known before the VM boots. It is recorded in
~/.ssh/known_hosts for the forwarded ports, which is where server-setup looks
first; server-setup then never needs ssh-keyscan (macOS's ssh-keyscan returns
nothing from Debian 13's sshd when scanning several key types at once) and the
harness's own connections verify the key strictly.

Egress: with QEMU user-mode networking every guest connection, DNS included,
is made on the host by the qemu-system-x86_64 process. Anything on the host
that blocks that process makes the guest look like it has "no DNS".
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

KNOWN_HOSTS = Path.home() / ".ssh" / "known_hosts"
EGRESS_PROBE_HOST = "deb.debian.org"


def generate_host_key(key_path: Path) -> str:
    """Create a fresh ed25519 host key pair at key_path; return the public key."""
    key_path.unlink(missing_ok=True)
    key_path.with_suffix(".pub").unlink(missing_ok=True)
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "boxmunge-vm-test",
         "-f", str(key_path)],
        check=True, capture_output=True,
    )
    return key_path.with_suffix(".pub").read_text().strip()


def cloud_init_host_key_block(key_path: Path) -> str:
    """cloud-config lines that install key_path as the VM's only host key."""
    private = key_path.read_text().strip().splitlines()
    public = " ".join(key_path.with_suffix(".pub").read_text().split()[:2])
    lines = [
        "ssh_deletekeys: true",
        "ssh_genkeytypes: []",
        "ssh_keys:",
        "  ed25519_private: |",
        *(f"    {line}" for line in private),
        f"  ed25519_public: {public}",
    ]
    return "\n".join(lines)


def _pattern(port: int) -> str:
    return f"[localhost]:{port}"


def forget_host_keys(ports: list[int], known_hosts: Path = KNOWN_HOSTS) -> None:
    """Remove the VM's entries for ports from known_hosts."""
    for port in ports:
        subprocess.run(["ssh-keygen", "-R", _pattern(port), "-f", str(known_hosts)],
                       capture_output=True, check=False)


def trust_host_key(public_key: str, ports: list[int],
                   known_hosts: Path = KNOWN_HOSTS) -> None:
    """Record the VM's host key for each forwarded port in known_hosts."""
    key_type, key_b64 = public_key.split()[:2]
    forget_host_keys(ports, known_hosts)
    known_hosts.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(known_hosts, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a") as f:
        for port in ports:
            f.write(f"{_pattern(port)} {key_type} {key_b64}\n")


def check_guest_egress(ssh_run, port: int) -> None:
    """Fail loudly unless the guest can resolve and reach the internet.

    ssh_run is the harness's ssh_run(user, port, command, check) helper.
    """
    dns = ssh_run("test", port, f"timeout 15 getent hosts {EGRESS_PROBE_HOST}",
                  check=False)
    https = ssh_run("test", port,
                    f"curl -sS -o /dev/null --max-time 15 https://{EGRESS_PROBE_HOST}/",
                    check=False)
    if dns.returncode == 0 and https.returncode == 0:
        return
    raise RuntimeError(
        "The VM has no outbound network.\n"
        f"  DNS   (getent hosts {EGRESS_PROBE_HOST}): "
        f"{'ok' if dns.returncode == 0 else 'FAILED'}\n"
        f"  HTTPS (curl https://{EGRESS_PROBE_HOST}/): "
        f"{'ok' if https.returncode == 0 else 'FAILED ' + https.stderr.strip()}\n"
        "QEMU user-mode networking makes every guest connection, DNS included, "
        "from the host's qemu-system-x86_64 process. If the host itself is online, "
        "something on the host is blocking that process: check application "
        "firewalls such as Little Snitch or LuLu. Homebrew's qemu is ad-hoc "
        "signed, so a rule that allowed it stops matching after `brew upgrade "
        "qemu`. Allow outbound connections for "
        f"{_qemu_binary()} and rerun."
    )


def _qemu_binary() -> str:
    result = subprocess.run(["which", "qemu-system-x86_64"],
                            capture_output=True, text=True, check=False)
    path = result.stdout.strip()
    return str(Path(path).resolve()) if path else "qemu-system-x86_64"
