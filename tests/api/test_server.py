# SPDX-License-Identifier: Apache-2.0
"""apid's HTTP transport, over real unix sockets."""
from __future__ import annotations

import socket
import stat
import threading

import pytest

from boxmunge.api import server as server_module
from boxmunge.api.dev.fixture_host import FixtureHost
from boxmunge.api.jobs import JobStore
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.registry import Action, Registry
from boxmunge.api.schema import BOOLEAN, obj
from boxmunge.api.server import ApiApp, ServerError, prepare_socket_path
from tests.api.fakes import make_invoker
from tests.api.unix_http import call, raw_exchange, serving

WEBUI = Principal.plugin("webui", Tier.OBSERVE)
OBSERVE_ONLY = frozenset({Tier.OBSERVE})


@pytest.fixture
def fixture_app(fixture_paths) -> ApiApp:
    invoker = make_invoker(fixture_paths, host=FixtureHost(fixture_paths),
                           served_tiers=OBSERVE_ONLY)
    return ApiApp(invoker, WEBUI, mode="dev")


@pytest.fixture
def served(fixture_app, sock_path):
    with serving(fixture_app, sock_path):
        yield sock_path


def _test_app(paths, *handlers: tuple[str, object]) -> ApiApp:
    registry = Registry()
    for name, handler in handlers:
        registry.register(Action(name=name, tier=Tier.OBSERVE, summary="Test.",
                                 params=obj({}), result=obj({"ok": BOOLEAN}),
                                 handler=handler))
    return ApiApp(make_invoker(paths, registry=registry), WEBUI, mode="dev")


def test_catalog(served) -> None:
    status, body = call(served, "GET", "/v1/actions")
    assert status == 200 and body["api_version"] == "1.0" and body["ok"] is True
    data = body["data"]
    assert (data["principal"], data["mode"]) == ("plugin:webui", "dev")
    assert {entry["tier"] for entry in data["actions"]} == {"observe"}
    assert set(data["actions"][0]) == {"name", "tier", "summary", "params", "result", "job"}


def test_invoke(served) -> None:
    status, body = call(served, "POST", "/v1/actions/project.get",
                        {"params": {"project": "billing"}})
    assert status == 200 and body["action"] == "project.get"
    assert body["data"]["lifecycle"] == "quarantined"


def test_job_route(served, fixture_paths) -> None:
    job_id = JobStore(fixture_paths).recent()[0]["id"]
    status, body = call(served, "GET", f"/v1/jobs/{job_id}")
    assert status == 200 and body["data"]["id"] == job_id


@pytest.mark.parametrize("method,path,body,status,code", [
    ("POST", "/v1/actions/nope.nope", {"params": {}}, 404, "not_found"),
    ("POST", "/v1/actions/project.get", {"params": {"project": "shop\n"}}, 422,
     "invalid_params"),
    ("GET", "/v1/events", None, 404, "not_found"),
    ("GET", "/v1/jobs/01JAAAAAAAAAAAAAAAAAAAAAA1/events", None, 404, "not_found"),
    ("POST", "/v1/approvals", {"action": "project.rollback"}, 404, "not_found"),
    ("DELETE", "/v1/actions/status.get", None, 404, "not_found"),
])
def test_errors_are_json_envelopes(served, method, path, body, status, code) -> None:
    got_status, got = call(served, method, path, body)
    assert (got_status, got["ok"], got["error"]["code"]) == (status, False, code)
    assert got["api_version"] == "1.0" and got["error"]["message"]


@pytest.mark.parametrize("body,message", [
    (b"not json", "not valid JSON"),
    (b"\xff\xfe", "not valid JSON"),
    (b'{"params": {"tail": NaN}}', "not valid JSON"),
    (b"[]", "must be a JSON object"),
    (b"{}", 'needs "params"'),
    (b'{"params": []}', "params must be a JSON object"),
    (b'{"params": {}, "extra": 1}', "Unexpected request field(s): extra"),
    (b'{"params": {}, "approval": "yes"}', "approval must be a JSON object"),
])
def test_malformed_bodies_are_invalid_params_and_the_server_carries_on(
        served, body, message) -> None:
    status, got = call(served, "POST", "/v1/actions/status.get", body)
    assert status == 422 and message in got["error"]["message"]
    assert call(served, "POST", "/v1/actions/status.get", {"params": {}})[0] == 200


@pytest.mark.parametrize("request_bytes,status,message", [
    (b"POST /v1/actions/status.get HTTP/1.1\r\nHost: x\r\n\r\n", 422, "Content-Length"),
    (b"POST /v1/actions/status.get HTTP/1.1\r\nHost: x\r\nContent-Length: 999999\r\n\r\n",
     422, "the limit is 65536"),
    (b"POST /v1/actions/status.get HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
     422, "Chunked"),
    (b"POST /v1/actions/status.get HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n"
     b"Transfer-Encoding: chunked\r\n\r\n{}", 422, "Chunked"),
    (b"GET /v1/actions HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}",
     400, "GET takes no request body"),
    (b"GET /v1/actions HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
     400, "GET takes no request body"),
    # "\xb2" is a superscript two once headers are decoded as Latin-1: str.isdigit()
    # accepts it, int() does not.
    (b"POST /v1/actions/status.get HTTP/1.1\r\nHost: x\r\nContent-Length: \xb2\r\n\r\n",
     422, "Content-Length"),
    (b"GET /v1/actions HTTP/1.1\r\nX-Long: " + b"a" * 70000 + b"\r\n\r\n", 431, "Line too long"),
])
def test_bad_framing_is_refused_and_the_server_carries_on(
        served, request_bytes, status, message) -> None:
    got_status, got = raw_exchange(served, request_bytes)
    assert got_status == status and message in got["error"]["message"]
    assert got["api_version"] == "1.0"
    assert call(served, "GET", "/v1/actions")[0] == 200


SMUGGLED = b"GET /v1/actions HTTP/1.1\r\nHost: x\r\n\r\n"


@pytest.mark.parametrize("method", [b"GET", b"DELETE"])
def test_a_body_on_a_bodiless_request_is_never_parsed_as_the_next_request(
        served, method) -> None:
    """On keep-alive, an unread body would be read as a second request:
    a request-smuggling primitive once a proxy relays to apid."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(str(served))
        sock.sendall(method + b" /v1/actions HTTP/1.1\r\nHost: x\r\n"
                     + f"Content-Length: {len(SMUGGLED)}\r\n\r\n".encode() + SMUGGLED)
        chunks = []
        while chunk := sock.recv(65536):
            chunks.append(chunk)
    assert b"".join(chunks).count(b"HTTP/1.1 ") == 1
    assert call(served, "GET", "/v1/actions")[0] == 200


def test_a_stalled_client_is_dropped_and_the_server_carries_on(
        served, monkeypatch) -> None:
    """A body shorter than its Content-Length, or an idle keep-alive
    connection, must not hold a server thread forever. The production
    timeout is shortened here so the test is quick."""
    assert 0 < server_module.REQUEST_TIMEOUT <= 60
    assert server_module._RequestHandler.timeout == server_module.REQUEST_TIMEOUT
    monkeypatch.setattr(server_module._RequestHandler, "timeout", 0.3)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(str(served))
        sock.sendall(b"POST /v1/actions/status.get HTTP/1.1\r\nHost: x\r\n"
                     b"Content-Length: 100\r\n\r\n{}")
        assert sock.recv(65536) == b""  # closed by the server, not by our timeout
    assert call(served, "GET", "/v1/actions")[0] == 200


def test_socket_is_private_to_its_owner(served) -> None:
    assert stat.S_IMODE(served.stat().st_mode) == 0o600


def test_requests_are_served_concurrently(paths, sock_path) -> None:
    released = threading.Event()

    def block(params, ctx):
        return {"ok": released.wait(timeout=5)}

    def release(params, ctx):
        released.set()
        return {"ok": True}

    app = _test_app(paths, ("test.block", block), ("test.release", release))
    with serving(app, sock_path):
        results = []
        waiter = threading.Thread(target=lambda: results.append(
            call(sock_path, "POST", "/v1/actions/test.block", {"params": {}})))
        waiter.start()
        assert call(sock_path, "POST", "/v1/actions/test.release", {"params": {}})[0] == 200
        waiter.join(timeout=10)
    assert results and results[0][1]["data"] == {"ok": True}


def test_a_handler_bug_is_a_500_and_the_server_carries_on(paths, sock_path) -> None:
    def boom(params, ctx):
        raise RuntimeError("kaboom")

    app = _test_app(paths, ("test.boom", boom), ("test.fine", lambda p, c: {"ok": True}))
    with serving(app, sock_path):
        status, body = call(sock_path, "POST", "/v1/actions/test.boom", {"params": {}})
        assert status == 500 and body["error"]["code"] == "failed"
        assert "internal error: RuntimeError: kaboom" in body["error"]["message"]
        assert call(sock_path, "POST", "/v1/actions/test.fine", {"params": {}})[0] == 200
    assert "internal error serving POST /v1/actions/test.boom" in paths.log_file.read_text()


def test_stale_socket_is_cleared(sock_path) -> None:
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(sock_path))
    stale.close()  # the file stays; nothing listens
    prepare_socket_path(sock_path)
    assert not sock_path.exists()


def test_live_socket_is_refused(served) -> None:
    with pytest.raises(ServerError, match="already listening"):
        prepare_socket_path(served)
    assert call(served, "GET", "/v1/actions")[0] == 200


def test_a_file_that_is_not_a_socket_is_refused(sock_path) -> None:
    sock_path.write_text("precious")
    with pytest.raises(ServerError, match="not a socket"):
        prepare_socket_path(sock_path)
    assert sock_path.read_text() == "precious"


def test_a_missing_path_needs_nothing(sock_path) -> None:
    prepare_socket_path(sock_path)
    assert not sock_path.exists()
