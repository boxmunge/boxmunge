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
    # Stop requests are held back until the handler is installed and we are inside
    # the try below, so a stop at any point after the bind unwinds through the
    # socket cleanup.
    held = signal.pthread_sigmask(signal.SIG_BLOCK, _STOP_SIGNALS)
    server = UnixHTTPServer(socket_path, app, socket_mode=DEV_SOCKET_MODE, access_log=True)
    stop = _ShutdownRequest(server)
    stop.start_stopper()
    for sig in _STOP_SIGNALS:
        signal.signal(sig, stop)
    watcher_failure: list[OSError] = []
    try:
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, held)
            if exit_on_stdin_eof:
                threading.Thread(target=_stop_at_stdin_eof, args=(stop, watcher_failure),
                                 daemon=True).start()
            print(f"boxmunge-apid DEV MODE: serving the fixture box {root} on {socket_path} "
                  f"as plugin:{plugin}, observe actions only. Not a real box. Ctrl-C stops.",
                  file=sys.stderr)
            server.serve_forever()
        finally:
            server.server_close()
            socket_path.unlink(missing_ok=True)
        unwatched = (f"cannot watch stdin for --exit-on-stdin-eof: {watcher_failure[0]}"
                     if watcher_failure else None)
        try:
            server.drain()  # nothing may still be running (or printing) as the interpreter exits
        except ServerError as e:
            raise ServerError(f"{e}; also {unwatched}" if unwatched else str(e)) from e
        if unwatched:
            raise ServerError(unwatched)
    finally:
        stop.close()


_STDIN_FD = 0
_STOP_SIGNALS = frozenset({signal.SIGTERM, signal.SIGINT})


class _ShutdownRequest:
    """Ask serve_forever to return, from a signal handler or a watcher thread.

    It must only request: raising out of a handler lands in arbitrary
    socketserver code, and anything that takes a lock (starting a thread,
    Event.set) can deadlock when a second signal runs a nested handler on the
    thread that holds it. So a request is one non-blocking write to a pipe (the
    self-pipe trick); a stopper thread, started once beforehand, blocks reading
    it and then calls shutdown(), which blocks until serve_forever returns and
    so can never run on the main thread."""

    def __init__(self, server: UnixHTTPServer) -> None:
        self._server = server
        self._read, self._write = os.pipe()
        os.set_blocking(self._write, False)
        self._stopper = threading.Thread(target=self._stop_when_asked, daemon=True)

    def start_stopper(self) -> None:
        self._stopper.start()

    def _stop_when_asked(self) -> None:
        os.read(self._read, 1)  # a byte, or EOF once close() runs
        self._server.shutdown()

    def __call__(self, signum: int, frame: Any) -> None:
        self.request()

    def request(self) -> None:
        try:
            os.write(self._write, b"x")
        except BlockingIOError:
            pass  # a full pipe already means "requested"

    def close(self) -> None:
        """Serving is over: nothing is left to stop, so late stop signals are
        ignored rather than written to a closed pipe."""
        for sig in _STOP_SIGNALS:
            signal.signal(sig, signal.SIG_IGN)
        os.close(self._write)  # wakes a stopper that was never asked
        self._stopper.join()
        os.close(self._read)


def _stop_at_stdin_eof(stop: _ShutdownRequest, failure: list[OSError]) -> None:
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
    stop.request()


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
