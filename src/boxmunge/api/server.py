# SPDX-License-Identifier: Apache-2.0
"""HTTP/1.1 with JSON bodies over a unix socket: how apid serves actions.

ApiApp turns a request into an Invoker call and an envelope; the request
handler only moves bytes. The principal is fixed when the server starts,
from the socket it listens on, and nothing a client sends can change it.

Every response body is JSON and carries api_version:
  {"api_version": "1.0", "ok": true, "action": "...", "data": {...}}
  {"api_version": "1.0", "ok": false, "error": {"code", "message", "details"?}}
"""
from __future__ import annotations

import json
import os
import re
import secrets
import socket
import socketserver
import stat
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from boxmunge.api import API_VERSION
from boxmunge.api.invoke import Invoker
from boxmunge.api.principal import Principal
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.log import log_error

MAX_BODY_BYTES = 64 * 1024
# Seconds a connection may sit without sending: a client that stalls
# mid-body or idles on keep-alive is dropped rather than pinning a thread.
REQUEST_TIMEOUT = 30.0
# Connections served at once; one more is answered 503 and closed.
MAX_CONNECTIONS = 16
# Seconds a stopping server gives in-flight requests to finish.
DRAIN_TIMEOUT = 5.0
_CONTENT_LENGTH_RE = re.compile(r"[0-9]{1,9}")
_BODY_KEYS = frozenset({"params", "approval"})
_ACTIONS_PREFIX = "/v1/actions/"
_JOBS_PREFIX = "/v1/jobs/"
# Request lines are client-chosen: C0 controls and DEL are logged as \xNN so
# no escape sequence reaches the developer's terminal.
_CONTROL_ESCAPES = {c: f"\\x{c:02x}" for c in (*range(0x20), 0x7f)}


class ServerError(Exception):
    """The server cannot start on the requested socket."""


_DUPLICATE_LENGTH = "Send exactly one Content-Length header."


class _BadFraming(Exception):
    """A request the HTTP layer refuses before any action is looked up."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class ApiApp:
    def __init__(self, invoker: Invoker, principal: Principal, *, mode: str) -> None:
        self._invoker = invoker
        self._principal = principal
        self._mode = mode

    def handle(self, method: str, target: str,
               body: bytes | None) -> tuple[int, dict[str, Any]]:
        """Serve one request; returns (HTTP status, JSON body)."""
        path = urlsplit(target).path
        try:
            return 200, self._route(method, path, body)
        except ActionError as e:
            return e.http_status, error_body(e)
        except Exception as e:
            log_error("apid", f"internal error serving {method} {path}: {e}",
                      self._invoker.paths, detail={"traceback": traceback.format_exc()})
            error = ActionError(ErrorCode.FAILED,
                                f"internal error: {type(e).__name__}: {e}. The operational "
                                f"log has the traceback.")
            return error.http_status, error_body(error)

    def _route(self, method: str, path: str, body: bytes | None) -> dict[str, Any]:
        if method == "GET" and path == "/v1/actions":
            return ok_body({"principal": self._principal.id, "mode": self._mode,
                            "actions": self._invoker.catalog(self._principal)})
        if method == "POST" and path.startswith(_ACTIONS_PREFIX):
            params, approval = parse_invoke_body(body)
            result = self._invoker.invoke(path[len(_ACTIONS_PREFIX):], params,
                                          self._principal, approval)
            return ok_body(result.data, action=result.action)
        if method == "GET" and path.startswith(_JOBS_PREFIX) and path.count("/") == 3:
            result = self._invoker.invoke("job.get", {"id": path[len(_JOBS_PREFIX):]},
                                          self._principal)
            return ok_body(result.data, action=result.action)
        raise ActionError(ErrorCode.NOT_FOUND,
                          f"No endpoint {method} {path}. docs/PLUGIN_API.md lists the "
                          f"endpoints.")


def ok_body(data: dict[str, Any], *, action: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"api_version": API_VERSION, "ok": True}
    if action is not None:
        body["action"] = action
    body["data"] = data
    return body


def error_body(error: ActionError) -> dict[str, Any]:
    return {"api_version": API_VERSION, "ok": False, "error": error.to_dict()}


def _reject_constant(name: str) -> None:
    raise ValueError(f"{name} is not valid JSON")


def parse_invoke_body(body: bytes | None) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """(params, approval) from a POST /v1/actions/<name> body."""
    if not body:
        raise ActionError(ErrorCode.INVALID_PARAMS,
                          'The request body must be a JSON object: {"params": {...}}.')
    try:
        doc = json.loads(body.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError) as e:
        raise ActionError(ErrorCode.INVALID_PARAMS,
                          f"The request body is not valid JSON: {e}") from e
    except RecursionError as e:
        raise ActionError(ErrorCode.INVALID_PARAMS,
                          "The request body is nested too deeply.") from e
    if not isinstance(doc, dict):
        raise ActionError(ErrorCode.INVALID_PARAMS, "The request body must be a JSON object.")
    unknown = sorted(set(doc) - _BODY_KEYS)
    if unknown:
        raise ActionError(ErrorCode.INVALID_PARAMS,
                          f"Unexpected request field(s): {', '.join(unknown)}. "
                          f"Allowed: params, approval.")
    if "params" not in doc:
        raise ActionError(ErrorCode.INVALID_PARAMS,
                          'The request body needs "params"; send {} for none.')
    if not isinstance(doc["params"], dict):
        raise ActionError(ErrorCode.INVALID_PARAMS, "params must be a JSON object.")
    approval = doc.get("approval")
    if "approval" in doc and not isinstance(approval, dict):
        raise ActionError(ErrorCode.INVALID_PARAMS, "approval must be a JSON object.")
    return doc["params"], approval


class _RequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "boxmunge-apid"
    sys_version = ""
    timeout = REQUEST_TIMEOUT
    server: UnixHTTPServer

    def handle_one_request(self) -> None:
        """Serve one request, which must arrive whole (headers and body)
        within REQUEST_TIMEOUT. The per-read timeout alone would let a
        client trickling a byte at a time hold the thread indefinitely."""
        self._watchdog = threading.Timer(REQUEST_TIMEOUT, self._expire)
        self._watchdog.daemon = True
        self._watchdog.start()
        try:
            super().handle_one_request()
        finally:
            self._watchdog.cancel()

    def _expire(self) -> None:
        try:
            self.connection.shutdown(socket.SHUT_RD)  # pending reads see EOF
        except OSError:
            pass

    def _refuse(self, status: int, message: str) -> None:
        self.close_connection = True
        self._respond(status, {"api_version": API_VERSION, "ok": False, "error": {
            "code": ErrorCode.INVALID_PARAMS.value, "message": message}})

    def do_GET(self) -> None:
        self._watchdog.cancel()
        if self._duplicate_length():
            self._refuse(400, _DUPLICATE_LENGTH)
            return
        if self._declares_body():
            # Never leave a body unread on a kept-alive connection: it would
            # be parsed as the next request.
            self._refuse(400, "A GET takes no request body; send none.")
            return
        self._respond(*self.server.app.handle("GET", self.path, None))

    def _duplicate_length(self) -> bool:
        return len(self.headers.get_all("Content-Length") or []) > 1

    def _declares_body(self) -> bool:
        return (self.headers.get("Transfer-Encoding") is not None
                or self.headers.get("Content-Length") not in (None, "0"))

    def do_POST(self) -> None:
        try:
            body = self._read_body()
        except _BadFraming as e:
            self._refuse(e.status, e.message)
            return
        except ActionError as e:
            self.close_connection = True
            self._respond(e.http_status, error_body(e))
            return
        finally:
            self._watchdog.cancel()
        self._respond(*self.server.app.handle("POST", self.path, body))

    def _not_served(self) -> None:
        self._watchdog.cancel()
        self.close_connection = True  # any body is left unread
        self._respond(*self.server.app.handle(self.command, self.path, None))

    do_PUT = do_DELETE = do_PATCH = _not_served

    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding") is not None:
            raise ActionError(ErrorCode.INVALID_PARAMS,
                              "Chunked request bodies are not supported; send Content-Length.")
        if self._duplicate_length():
            raise _BadFraming(400, _DUPLICATE_LENGTH)
        raw = self.headers.get("Content-Length")
        if raw is None or not _CONTENT_LENGTH_RE.fullmatch(raw):
            raise ActionError(ErrorCode.INVALID_PARAMS,
                              "A POST needs a Content-Length header giving the body size "
                              "in decimal digits.")
        length = int(raw)
        if length > MAX_BODY_BYTES:
            raise ActionError(ErrorCode.INVALID_PARAMS,
                              f"The request body is {length} bytes; the limit is "
                              f"{MAX_BODY_BYTES}.")
        body = self.rfile.read(length)
        if len(body) < length:
            raise _BadFraming(408, f"The request did not arrive whole within "
                                   f"{REQUEST_TIMEOUT:g} seconds.")
        return body

    def _respond(self, status: int, body: dict[str, Any]) -> None:
        payload = (json.dumps(body) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def send_error(self, code: int, message: str | None = None,
                   explain: str | None = None) -> None:
        """Malformed HTTP gets a JSON envelope too, never an HTML page."""
        self.close_connection = True
        error = {"code": ErrorCode.INVALID_PARAMS.value,
                 "message": message or "Malformed HTTP request."}
        self._respond(code, {"api_version": API_VERSION, "ok": False, "error": error})

    def address_string(self) -> str:
        return "unix"  # a unix socket peer has no address

    def log_message(self, format: str, *args: Any) -> None:
        if self.server.access_log:
            sys.stderr.write(f"apid: {(format % args).translate(_CONTROL_ESCAPES)}\n")


class UnixHTTPServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, socket_path: Path, app: ApiApp, *, socket_mode: int,
                 access_log: bool = False) -> None:
        self.app = app
        self.access_log = access_log
        self._socket_mode = socket_mode
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._max_connections = MAX_CONNECTIONS
        self._live: set[Any] = set()  # connections with a request thread running
        self._live_changed = threading.Condition()
        super().__init__(str(socket_path), _RequestHandler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            self._refuse_busy(request)
            return
        with self._live_changed:
            self._live.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            self._request_done(request)
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()
            self._request_done(request)

    def _request_done(self, request: Any) -> None:
        with self._live_changed:
            self._live.discard(request)
            self._live_changed.notify_all()

    def drain(self, timeout: float = DRAIN_TIMEOUT) -> None:
        """After serve_forever has returned: let running requests finish and
        drop idle keep-alive connections, so no handler thread is still alive
        (and possibly printing) when the process exits."""
        with self._live_changed:
            for request in self._live:
                try:
                    request.shutdown(socket.SHUT_RD)  # an idle read sees EOF
                except OSError:
                    pass
            if not self._live_changed.wait_for(lambda: not self._live, timeout):
                raise ServerError(f"{len(self._live)} requests still running "
                                  f"{timeout:g}s after shutdown")

    def _refuse_busy(self, request: Any) -> None:
        error = ActionError(ErrorCode.UNAVAILABLE,
                            f"apid is already serving {self._max_connections} connections; "
                            f"retry shortly.")
        payload = (json.dumps(error_body(error)) + "\n").encode()
        head = (f"HTTP/1.1 {error.http_status} Service Unavailable\r\n"
                f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n"
                f"Connection: close\r\n\r\n").encode()
        try:
            request.settimeout(1)
            request.sendall(head + payload)
        except OSError:
            pass
        finally:
            self.shutdown_request(request)

    def server_bind(self) -> None:
        """Bind inside a fresh 0700 directory, set the socket's mode there,
        then link it to the published path. Binding at the path directly
        would expose the socket with the process umask until a chmod. The
        link fails, leaving the path alone, if anything already holds it.
        The staging directory sits beside the target and is named relative
        to it as given, so a relative path stays short under AF_UNIX's
        ~104-byte limit however deep the working directory is."""
        target = str(self.server_address)
        private = os.path.join(os.path.dirname(target), f".apid-{secrets.token_hex(6)}")
        staged = os.path.join(private, "s")
        try:
            os.mkdir(private, 0o700)
            os.chmod(private, 0o700)
            try:
                self.socket.bind(staged)
                os.chmod(staged, self._socket_mode)
                os.link(staged, target)
            finally:
                if os.path.lexists(staged):
                    os.unlink(staged)
                os.rmdir(private)
        except OSError as e:
            raise ServerError(f"cannot listen on {target}: {e}") from e
        self.server_address = target


def prepare_socket_path(path: Path) -> None:
    """Clear a stale socket left by a crashed server; refuse anything in use.

    A path that is not a socket, or a socket another server is listening on,
    raises ServerError and is left alone.
    """
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(mode):
        raise ServerError(f"{path} exists and is not a socket; refusing to replace it")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.connect(str(path))
    except ConnectionRefusedError:
        path.unlink()
        return
    finally:
        probe.close()
    raise ServerError(f"another server is already listening on {path}")
