# SPDX-License-Identifier: Apache-2.0
"""Arguments for `boxmunge server-setup`."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass

from boxmunge_cli.server_setup import validate
from boxmunge_cli.server_setup.target import is_ip_address, parse_target

DESCRIPTION = """\
Turn a fresh Debian VPS into a boxmunge server. Connects as [user@]host
(default user root; a non-root user needs passwordless sudo), runs pre-flight
checks, then installs the signed boxmunge release.

The release is downloaded and verified on this machine first: cosign must be
installed locally. Its keyless signature on SHA256SUMS must come from the
boxmunge release workflow for that tag, and the installer must match
SHA256SUMS. Nothing is installed if either check fails.

The server's SSH host key is verified too: a server not yet in
~/.ssh/known_hosts must match --host-key-fingerprint, or be confirmed at the
terminal after its fingerprint is shown. The verified key is recorded for
both the current port and the post-setup port.
"""


@dataclass
class ServerSetupArgs:
    user: str
    host: str
    port: int
    email: str
    ssh_key_arg: str | None = None
    hostname: str | None = None
    boxmunge_ssh_port: int = 922
    no_aide: bool = False
    no_crowdsec: bool = False
    no_auto_updates: bool = False
    self_signed_tls: bool = False
    yes: bool = False
    release: str | None = None
    local_bundle: str | None = None
    host_key_fingerprint: str | None = None


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {value!r}")
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"must be 1-65535: {value!r}")
    return port


def _fingerprint(value: str) -> str:
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", value):
        raise argparse.ArgumentTypeError(
            f"expected an OpenSSH SHA256 fingerprint like SHA256:abc...xyz, got {value!r}")
    return value


def _checked(check):
    def convert(value: str):
        try:
            return check(value)
        except ValueError as e:
            raise argparse.ArgumentTypeError(str(e))
    convert.__name__ = check.__name__
    return convert


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("target", metavar="[user@]host", type=_checked(parse_target),
                   help="Server to set up")
    p.add_argument("-p", "--port", type=_port, default=22,
                   help="Current SSH port of the server (default: 22)")
    p.add_argument("--email", required=True, type=_checked(validate.email),
                   help="Contact address for Let's Encrypt (never collected by boxmunge)")
    p.add_argument("--ssh-key", dest="ssh_key_arg", metavar="KEY",
                   help="Public key (file or inline) for the deploy and supervisor "
                        "users (default: from ssh-agent or ~/.ssh/*.pub)")
    p.add_argument("--hostname", help="Server's public hostname (default: the target "
                                      "when it is a name)")
    p.add_argument("--boxmunge-ssh-port", type=_port, default=922,
                   help="SSH port after setup (default: 922)")
    p.add_argument("--no-aide", action="store_true", help="Skip AIDE file integrity")
    p.add_argument("--no-crowdsec", action="store_true", help="Skip CrowdSec")
    p.add_argument("--no-auto-updates", action="store_true",
                   help="Skip unattended-upgrades")
    p.add_argument("--self-signed-tls", action="store_true",
                   help="Use self-signed TLS instead of Let's Encrypt (testing)")
    p.add_argument("--host-key-fingerprint", type=_fingerprint, metavar="SHA256:...",
                   help="Expected SSH host key fingerprint of a server not yet in "
                        "known_hosts (required with --yes for a new server)")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Do not ask for confirmation (required without a terminal)")
    source = p.add_mutually_exclusive_group()
    source.add_argument("--release", metavar="vX.Y.Z",
                        help="Install this signed release (default: the latest)")
    source.add_argument("--local-bundle", metavar="PATH",
                        help="Install an unverified locally built bundle "
                             "(development only)")


def from_namespace(ns: argparse.Namespace) -> ServerSetupArgs:
    """Build the setup arguments. Raises ValueError for an unusable hostname."""
    user, host = ns.target
    hostname = ns.hostname
    if hostname is None and not is_ip_address(host):
        hostname = host
    if hostname is not None:
        validate.dns_hostname(hostname, public=not ns.self_signed_tls)
    return ServerSetupArgs(
        user=user, host=host, port=ns.port, email=ns.email,
        ssh_key_arg=ns.ssh_key_arg, hostname=hostname,
        boxmunge_ssh_port=ns.boxmunge_ssh_port,
        no_aide=ns.no_aide, no_crowdsec=ns.no_crowdsec,
        no_auto_updates=ns.no_auto_updates, self_signed_tls=ns.self_signed_tls,
        yes=ns.yes, release=ns.release, local_bundle=ns.local_bundle,
        host_key_fingerprint=ns.host_key_fingerprint,
    )


def parse_args(argv: list[str]) -> ServerSetupArgs:
    """Parse server-setup arguments on their own (exits 2 on a usage error)."""
    p = argparse.ArgumentParser(prog="boxmunge server-setup", description=DESCRIPTION)
    add_arguments(p)
    try:
        return from_namespace(p.parse_args(argv))
    except ValueError as e:
        p.error(str(e))


def _cmd_server_setup(ns: argparse.Namespace) -> int:
    from boxmunge_cli.server_setup.command import run_server_setup
    try:
        setup_args = from_namespace(ns)
    except ValueError as e:
        print(f"boxmunge server-setup: error: {e}", file=sys.stderr)
        return 2
    return run_server_setup(setup_args)


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "server-setup", help="Set up a fresh Debian VPS as a boxmunge server",
        description=DESCRIPTION, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_arguments(p)
    p.set_defaults(func=_cmd_server_setup)
