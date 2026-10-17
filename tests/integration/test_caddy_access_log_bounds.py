"""Every field a real Caddy writes to boxmunge's access log is bounded.

CrowdSec's docker source drops a line over 64 KiB and loses the lines after
it. A real caddy:2-alpine serves boxmunge's generated site block over HTTP and
HTTPS (an internal-CA wildcard site), and a client in its network namespace
sends requests with every attribute a client controls as long as the server
takes. The test fails on any field that is neither dropped nor capped in
caddy.py nor bounded by Caddy itself, so a field a future Caddy adds fails
here. A second test keeps the capping regexps cheap next to plain JSON.
"""
from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path

import pytest

from boxmunge.caddy import ACCESS_LOG_DROPPED, ACCESS_LOG_FIELD_LIMITS, _access_log_lines
from boxmunge.caddy import generate_caddy_config
from tests.integration.conftest import skip_no_docker

pytestmark = [pytest.mark.integration, skip_no_docker]

CADDY = "caddy:2-alpine"
CLIENT = "python:3.13-slim-trixie"
HOST = "bmtest.example.com"
# Fields Caddy fills itself: fixed strings, numbers, addresses and a protocol
# version Go's server validates.
BOUNDED_BY_CADDY = frozenset({
    "level", "ts", "logger", "msg", "bytes_read", "duration", "size", "status",
    "request>remote_ip", "request>remote_port", "request>client_ip", "request>proto",
})
FIXED_ALLOWANCE = 2048  # the bounded fields and the keys, generously

# Raw requests: the request line and headers as long as Go's server accepts
# (about 20 KB in all), 0xFF throughout, which Caddy escapes into six bytes.
_HOSTILE = r'''
import socket, ssl, sys
FF, HOST = b"\xff", sys.argv[1].encode()
def send(connect, host, method):
    sock = connect()
    sock.sendall(method + b" /" + FF * 6000 + b"?q=" + FF * 1000 + b" HTTP/1.1\r\n"
                 + b"Host: " + host + b"\r\nUser-Agent: Nikto " + FF * 6000
                 + b"\r\nX-Other: " + FF * 2000 + b"\r\nConnection: close\r\n\r\n")
    while sock.recv(65536):
        pass
def plain():
    return socket.create_connection(("127.0.0.1", 80))
def tls():
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    return ctx.wrap_socket(socket.create_connection(("127.0.0.1", 443)),
                           server_hostname="w." + sys.argv[1])
# A long method is refused (405) before the handlers run, so it carries no
# User-Agent field; GET reaches the proxy (which fails: 502).
for method in (b"GET" + b"X" * 2000, b"GET"):
    send(plain, HOST, method)
    send(tls, b"a" * 3000 + b"." + HOST, method)
'''

_TIMING = r'''
import http.client, sys, time
uri, ua = "/" + "a" * 12000, "b" * 6000
for host in sys.argv[1:]:
    conn, start = http.client.HTTPConnection("127.0.0.1", 80), time.monotonic()
    for _ in range(300):
        conn.request("GET", uri, headers={"Host": host, "User-Agent": ua})
        conn.getresponse().read()
    print(host, time.monotonic() - start)
'''


def _run(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True, timeout=600, check=False)
    if check and result.returncode != 0:
        raise AssertionError(f"{args[:4]} exited {result.returncode}:\n{result.stdout}\n{result.stderr}")
    return result


def _start_caddy(tmp_path: Path, name: str, caddyfile_text: str) -> None:
    caddyfile = tmp_path / f"{name}.Caddyfile"
    caddyfile.write_text("{\n    admin off\n    local_certs\n}\n" + caddyfile_text)
    caddyfile.chmod(0o644)
    _run(["docker", "run", "-d", "--name", name, "--network", "none",
          "-v", f"{caddyfile}:/etc/caddy/Caddyfile:ro", CADDY])
    _run(["docker", "exec", name, "sh", "-c",
          "for i in $(seq 50); do wget -q -O /dev/null http://127.0.0.1:2080/ && exit 0;"
          " sleep 0.2; done; exit 1"])


_READY = "http://:2080 {\n    respond \"up\"\n}\n"  # not logged


@pytest.fixture
def caddy(tmp_path: Path):
    """The generated site block, proxied (to nothing: 502) over HTTP and an
    HTTPS wildcard."""
    name = f"bmtest-logbound-{uuid.uuid4().hex[:10]}"
    _start_caddy(tmp_path, name, _READY + generate_caddy_config({
        "project": "myapp", "hosts": [f"http://{HOST}", f"*.{HOST}"],
        "services": {"web": {"type": "frontend", "port": 3000, "routes": [{"path": "/"}]}},
    }))
    try:
        yield name
    finally:
        _run(["docker", "rm", "-f", name], check=False)


@pytest.fixture
def timed(tmp_path: Path):
    """Two Caddys, one with boxmunge's log block and one with
    plain JSON (one Caddy would share its log writer between them)."""
    names = {kind: f"bmtest-logbound-{kind}-{uuid.uuid4().hex[:8]}" for kind in ("ours", "plain")}
    blocks = {"ours": "\n".join(_access_log_lines()),
              "plain": "    log {\n        output stdout\n        format json\n    }"}
    try:
        for kind, name in names.items():
            _start_caddy(tmp_path, name, _READY + f"http://{HOST} {{\n{blocks[kind]}\n"
                                                  "    respond \"ok\"\n}\n")
        yield names
    finally:
        for name in names.values():
            _run(["docker", "rm", "-f", name], check=False)


def _client(caddy: str, program: str, *args: str) -> str:
    return _run(["docker", "run", "--rm", "--network", f"container:{caddy}",
                 "--name", f"bmtest-logbound-client-{uuid.uuid4().hex[:10]}", CLIENT,
                 "python3", "-I", "-c", program, *args]).stdout


def _paths(doc: dict, prefix: str = "") -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in doc.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(_paths(value, f"{path}>"))
        else:
            out[path] = value
    return out


def _lines(caddy: str) -> list[str]:
    return _run(["docker", "logs", caddy]).stdout.splitlines()


def test_every_logged_field_is_dropped_capped_or_bounded_by_caddy(caddy) -> None:
    _client(caddy, _HOSTILE, HOST)
    lines = _lines(caddy)
    assert len(lines) == 4, lines  # both methods, over HTTP and HTTPS
    bound = 6 * sum(ACCESS_LOG_FIELD_LIMITS.values()) + FIXED_ALLOWANCE
    for line in lines:
        assert len(line) <= bound
        fields = _paths(json.loads(line))
        unbounded = set(fields) - BOUNDED_BY_CADDY - set(ACCESS_LOG_FIELD_LIMITS)
        assert not unbounded, f"cap or drop these in caddy.py: {sorted(unbounded)}"
        for dropped in ACCESS_LOG_DROPPED:
            assert not any(p == dropped or p.startswith(f"{dropped}>") for p in fields)
        for path, limit in ACCESS_LOG_FIELD_LIMITS.items():
            assert len(str(fields.get(path, ""))) <= limit, path
    # Every capped field a client sets was long enough to be cut (the long
    # host only matches the wildcard site, so only over HTTPS).
    for path in ("request>uri", "request>host", "request>method", "user_agent"):
        longest = max(len(str(_paths(json.loads(line)).get(path, ""))) for line in lines)
        assert longest == ACCESS_LOG_FIELD_LIMITS[path], path


def test_capping_costs_little_next_to_plain_json(timed) -> None:
    """Fixed-width groups, not `.{0,n}`: a bounded range made each long request
    cost Go's regexp engine tens of milliseconds, enough to saturate Caddy."""
    took = {kind: float(_client(name, _TIMING, HOST).split()[1]) for kind, name in timed.items()}
    assert took["ours"] < 3 * took["plain"] + 1.0, took
