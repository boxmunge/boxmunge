# SPDX-License-Identifier: Apache-2.0
"""boxmunge-apid: serve the action API over a unix socket.

This release has two modes, both for plugin authors working on a laptop:

  boxmunge-apid --make-fixture DIR
  boxmunge-apid --dev --root DIR --socket ./api.sock [--plugin NAME]

Dev mode serves only a fixture box (a directory carrying .boxmunge-fixture),
only observe actions, and only as plugin:NAME with an observe grant.
Serving a real box to an installed plugin, through per-plugin systemd socket
units, arrives with plugin installation.
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
from pathlib import Path
from typing import Any

from boxmunge.api.actions import build_registry
from boxmunge.api.audit import AuditLog
from boxmunge.api.dev.fixture import FixtureError, make_fixture, require_fixture
from boxmunge.api.dev.fixture_host import FixtureHost
from boxmunge.api.invoke import Invoker
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.server import ApiApp, ServerError, UnixHTTPServer, prepare_socket_path
from boxmunge.paths import BoxPaths

DEV_SOCKET_MODE = 0o600
DEV_SERVED_TIERS = frozenset({Tier.OBSERVE})


def build_dev_app(root: Path, plugin: str) -> ApiApp:
    """The app dev mode serves: the fixture at *root*, observe only."""
    require_fixture(root)
    paths = BoxPaths(root.resolve())
    invoker = Invoker(build_registry(), paths, FixtureHost(paths),
                      AuditLog(paths.audit_log), served_tiers=DEV_SERVED_TIERS)
    return ApiApp(invoker, Principal.plugin(plugin, Tier.OBSERVE), mode="dev")


def run_dev(root: Path, socket_path: Path, plugin: str, *, exit_on_stdin_eof: bool = False) -> None:
    app = build_dev_app(root, plugin)
    if exit_on_stdin_eof:
        os.fstat(_STDIN_FD)  # a closed stdin must fail now, not leave the server unwatched
    prepare_socket_path(socket_path)
    # The handler is in place and SIGTERM held back until we are inside the try below,
    # so a stop request at any point after the bind unwinds through the socket cleanup.
    signal.signal(signal.SIGTERM, _interrupt)
    held = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
    server = UnixHTTPServer(socket_path, app, socket_mode=DEV_SOCKET_MODE, access_log=True)
    watcher_failure: list[OSError] = []
    try:
        signal.pthread_sigmask(signal.SIG_SETMASK, held)
        if exit_on_stdin_eof:
            threading.Thread(target=_stop_at_stdin_eof, args=(watcher_failure,),
                             daemon=True).start()
        print(f"boxmunge-apid DEV MODE: serving the fixture box {root} on {socket_path} "
              f"as plugin:{plugin}, observe actions only. Not a real box. Ctrl-C stops.",
              file=sys.stderr)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        socket_path.unlink(missing_ok=True)
    if watcher_failure:
        raise ServerError(f"cannot watch stdin for --exit-on-stdin-eof: {watcher_failure[0]}")


_STDIN_FD = 0


def _stop_at_stdin_eof(failure: list[OSError]) -> None:
    """Stop the server when stdin closes, which is how a supervising process
    that is killed outright (no chance to signal us) still takes us down.
    A watcher that cannot read stops the server too, with a failure to report."""
    # Raw fd reads: a daemon thread blocked inside sys.stdin's buffered reader
    # holds its lock, and interpreter shutdown then aborts (SIGABRT) on it.
    try:
        while os.read(_STDIN_FD, 4096):
            pass
    except OSError as e:
        failure.append(e)
    os.kill(os.getpid(), signal.SIGTERM)


def _interrupt(signum: int, frame: Any) -> None:
    # One shot: a second stop request (an explicit SIGTERM racing the stdin-EOF
    # one) must not raise again inside the shutdown path and kill us with SIGINT.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise KeyboardInterrupt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="boxmunge-apid",
        description="Serve the boxmunge action API over a unix socket. This release "
                    "serves fixture boxes for plugin development only.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dev", action="store_true",
                      help="serve a fixture box made by --make-fixture")
    mode.add_argument("--make-fixture", type=Path, metavar="DIR",
                      help="write a realistic fixture box into DIR (new or empty)")
    parser.add_argument("--root", type=Path, metavar="DIR", help="fixture box to serve")
    parser.add_argument("--socket", type=Path, metavar="PATH", help="unix socket to listen on")
    parser.add_argument("--exit-on-stdin-eof", action="store_true",
                        help="with --dev: stop when stdin closes, so a supervising "
                             "process that dies cannot leave the server running")
    parser.add_argument("--plugin", default="dev", metavar="NAME",
                        help="plugin name the dev principal takes (default: dev)")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.make_fixture is not None and (args.root or args.socket):
        parser.error("--make-fixture takes only its directory")
    if args.dev and (args.root is None or args.socket is None):
        parser.error("--dev needs --root DIR and --socket PATH")
    if args.exit_on_stdin_eof and not args.dev:
        parser.error("--exit-on-stdin-eof only applies to --dev")
    try:
        if args.make_fixture is not None:
            make_fixture(args.make_fixture)
            print(f"Fixture box written to {args.make_fixture}.\n"
                  f"Serve it with: boxmunge-apid --dev --root {args.make_fixture} "
                  f"--socket ./api.sock")
            return
        run_dev(args.root, args.socket, args.plugin,
                    exit_on_stdin_eof=args.exit_on_stdin_eof)
    except (FixtureError, ServerError, ValueError, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
