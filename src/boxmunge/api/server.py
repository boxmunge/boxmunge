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
import socket
import socketserver
import stat
import sys
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
_CONTENT_LENGTH_RE = re.compile(r"[0-9]{1,9}")
_BODY_KEYS = frozenset({"params", "approval"})
_ACTIONS_PREFIX = "/v1/actions/"
_JOBS_PREFIX = "/v1/jobs/"


class ServerError(Exception):
    """The server cannot start on the requested socket."""


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

    def do_GET(self) -> None:
        self._respond(*self.server.app.handle("GET", self.path, None))

    def do_POST(self) -> None:
        try:
            body = self._read_body()
        except ActionError as e:
            self.close_connection = True
            self._respond(e.http_status, error_body(e))
            return
        self._respond(*self.server.app.handle("POST", self.path, body))

    def _not_served(self) -> None:
        self.close_connection = True  # any body is left unread
        self._respond(*self.server.app.handle(self.command, self.path, None))

    do_PUT = do_DELETE = do_PATCH = _not_served

    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding") is not None:
            raise ActionError(ErrorCode.INVALID_PARAMS,
                              "Chunked request bodies are not supported; send Content-Length.")
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
        return self.rfile.read(length)

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
            sys.stderr.write(f"apid: {format % args}\n")


class UnixHTTPServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, socket_path: Path, app: ApiApp, *, socket_mode: int,
                 access_log: bool = False) -> None:
        self.app = app
        self.access_log = access_log
        super().__init__(str(socket_path), _RequestHandler)
        os.chmod(socket_path, socket_mode)


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
