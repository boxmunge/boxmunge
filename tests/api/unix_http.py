# SPDX-License-Identifier: Apache-2.0
"""A minimal HTTP client over a unix socket, for the apid tests."""
from __future__ import annotations

import http.client
import json
import socket
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from boxmunge.api.server import ApiApp, UnixHTTPServer


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: Path, timeout: float = 10.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = str(socket_path)

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


def call(socket_path: Path, method: str, path: str,
         body: Any = None) -> tuple[int, dict[str, Any]]:
    """One request; *body* is JSON-encoded unless it is bytes or None."""
    payload = body if body is None or isinstance(body, bytes) else json.dumps(body).encode()
    conn = UnixHTTPConnection(socket_path)
    try:
        conn.request(method, path, body=payload,
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        return response.status, json.loads(response.read())
    finally:
        conn.close()


def raw_exchange(socket_path: Path, data: bytes, timeout: float = 5.0) -> tuple[int, dict]:
    """Send raw bytes; read until the server closes; parse status and body."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(str(socket_path))
        sock.sendall(data)
        chunks = []
        while chunk := sock.recv(65536):
            chunks.append(chunk)
    head, _, body = b"".join(chunks).partition(b"\r\n\r\n")
    return int(head.split(b" ", 2)[1]), json.loads(body)


@contextmanager
def serving(app: ApiApp, socket_path: Path) -> Iterator[UnixHTTPServer]:
    """Run a server on *socket_path* in a background thread."""
    server = UnixHTTPServer(socket_path, app, socket_mode=0o600)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                              daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        socket_path.unlink(missing_ok=True)
        thread.join(timeout=5)
