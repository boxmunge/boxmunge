"""How the VM test reaches the guest, and how the guest reaches the internet.

Host key: the harness generates the VM's ed25519 host key itself and hands it
to cloud-init, so the key is known before the VM boots. It is recorded in
~/.ssh/known_hosts for the forwarded ports, which is where server-setup looks
first; server-setup then never needs ssh-keyscan (whose unauthenticated
connections Debian 13's sshd penalises under PerSourcePenalties, so repeated
runs get empty scans) and the harness's own connections verify the key
strictly. The private key exists only in a 0700 temporary directory until the
cloud-init ISO is built.

Egress: with QEMU user-mode networking every guest connection, DNS included,
is made on the host by the qemu-system-x86_64 process. Anything on the host
that blocks that process makes the guest look like it has "no DNS".
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

KNOWN_HOSTS = Path.home() / ".ssh" / "known_hosts"
EGRESS_PROBE_HOST = "deb.debian.org"
# Debian and Docker packages, GitHub releases (cosign, boxmunge) and where
# their downloads redirect, Docker Hub and its layer store, Alpine packages
# (the system image's build).
EGRESS_HOSTS = (EGRESS_PROBE_HOST, "download.docker.com", "github.com",
                "release-assets.githubusercontent.com", "registry-1.docker.io",
                "production.cloudflare.docker.com", "dl-cdn.alpinelinux.org")
EGRESS_RETRY_PAUSES = (5, 10)  # seconds before the 2nd and 3rd attempt of each check


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
    """cloud-config lines that install key_path as the VM's only host key.

    With ssh_keys given, cloud-init writes those keys and generates none.
    """
    private = key_path.read_text().strip().splitlines()
    public = " ".join(key_path.with_suffix(".pub").read_text().split()[:2])
    lines = [
        "ssh_deletekeys: true",
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


def check_cloud_init(ssh_run, port: int) -> None:
    """Fail loudly unless cloud-init finished without errors or warnings.

    `cloud-init status` exits 0 only for a clean run: 1 is an error, 2 is
    "degraded" (e.g. a schema problem in our user-data).
    """
    result = ssh_run("test", port, "cloud-init status --wait --long", check=False)
    if result.returncode != 0:
        raise RuntimeError(
            f"cloud-init did not finish cleanly (exit {result.returncode}):\n"
            f"{result.stdout.strip()}\n{result.stderr.strip()}"
        )


def _probe(ssh_run, port: int, command: str, retry_command: str | None = None):
    """One host check, retried with a backoff: a single slow CDN answer (an
    IPv6 path timing out while IPv4 is fast) is not an unreachable host.
    Retries use retry_command (curl -4) when given."""
    for attempt, pause in enumerate((0, *EGRESS_RETRY_PAUSES)):
        if pause:
            time.sleep(pause)
        result = ssh_run("test", port, command if attempt == 0 else retry_command or command,
                         check=False)
        if result.returncode == 0:
            break
    return result


def _probe_egress(ssh_run, port: int) -> dict[str, object]:
    """DNS, then HTTPS to every host the install reaches; any HTTP answer
    (a 404 too) counts."""
    probes = {"DNS   (getent hosts " + EGRESS_PROBE_HOST + ")": _probe(
        ssh_run, port, f"timeout 15 getent hosts {EGRESS_PROBE_HOST}")}
    for host in EGRESS_HOSTS:
        curl = f"curl -sS -o /dev/null --max-time 15 {{}}https://{host}/"
        probes[f"HTTPS (curl https://{host}/)"] = _probe(
            ssh_run, port, curl.format(""), curl.format("-4 "))
    return probes


def _outcome(result, timed_out_code: int | None = None) -> str:
    if result.returncode == 0:
        return "ok"
    detail = result.stderr.strip()
    if timed_out_code is not None and result.returncode == timed_out_code:
        detail = (detail + " " if detail else "") + "(timed out)"
    return f"FAILED (exit {result.returncode}) {detail}".rstrip()


def check_guest_egress(ssh_run, port: int) -> None:
    """Fail loudly unless the guest can resolve names and reach every host
    the install needs. An application firewall may allow qemu to some hosts
    and not others: GitHub's release assets have been blocked while
    deb.debian.org was not.

    ssh_run is the harness's ssh_run(user, port, command, check) helper. Each
    check is attempted three times, 5s then 10s apart (the retries over IPv4),
    which covers a guest whose network is still settling and a CDN that is
    slow once.
    """
    probes = _probe_egress(ssh_run, port)
    if all(r.returncode == 0 for r in probes.values()):
        return
    report = "\n".join(f"  {what}: {_outcome(r, 124 if what.startswith('DNS') else None)}"
                       for what, r in probes.items())
    raise RuntimeError(
        "The VM cannot reach every host the install needs (each check tried three times).\n"
        f"{report}\n"
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
