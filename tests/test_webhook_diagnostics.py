"""Webhook diagnostics carry a safe endpoint label, the exception class and an
HTTP status, never exception text or any part of a secret-bearing URL (audit R08)."""
from __future__ import annotations

import io
import urllib.error
from unittest.mock import patch

import pytest

from boxmunge.paths import BoxPaths
from boxmunge.webhooks import _deliver, fire_webhook

SECRET = "DUMMYSECRET9f3a"
URLS = [
    f"https://hooks.example.com/{SECRET} x",           # InvalidURL quotes the target
    f"https://hooks.example.com/services/{SECRET}",
    f"https://hooks.example.com/hook?token={SECRET}",
    f"https://user:{SECRET}@hooks.example.com/hook",
    f"https://hooks.example.com:{SECRET}/hook",         # invalid port
    f"https://[{SECRET}/hook",                          # malformed host syntax
    f"https://hooks.example.com:99999/{SECRET}",        # out-of-range port
    f"https://{SECRET} bad/hook",                       # space in host
    f"{SECRET}",                                        # no scheme
]


def _config(url: str) -> dict:
    return {"hostname": "box", "webhooks": [{"url": url, "events": ["deploy"]}]}


def _refuse(*args, **kwargs):
    # A transport error whose text echoes the target, as a stack might.
    raise ConnectionRefusedError(f"connect to {args[0]} refused ({SECRET})")


@pytest.mark.parametrize("url", URLS)
def test_failures_and_the_log_carry_no_secret(paths: BoxPaths, url: str) -> None:
    with patch("socket.create_connection", _refuse):
        failures = fire_webhook("deploy", "app", _config(url))
        _deliver("deploy", "app", _config(url), None, paths)
    assert len(failures) == 1
    assert SECRET not in failures[0]
    assert SECRET not in paths.log_file.read_text()


def test_a_malformed_url_names_the_setting_not_its_value() -> None:
    failures = fire_webhook("deploy", "app", _config(f"https://hooks.example.com/{SECRET} x"))
    assert "webhooks" in failures[0] and "url" in failures[0] and "malformed" in failures[0]


def test_a_failure_says_host_exception_class_and_http_status() -> None:
    err = urllib.error.HTTPError(f"https://h.example.com/{SECRET}", 503, "busy", {}, io.BytesIO())
    with patch("urllib.request.urlopen", side_effect=err):
        (failure,) = fire_webhook("deploy", "app", _config(f"https://h.example.com/{SECRET}"))
    assert failure == "https://h.example.com: HTTPError (HTTP 503)"
    with patch("socket.create_connection", _refuse):
        (failure,) = fire_webhook("deploy", "app", _config("https://h.example.com/p"))
    assert failure.startswith("https://h.example.com: URLError (ConnectionRefusedError)")
