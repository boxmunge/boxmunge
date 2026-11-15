# SPDX-License-Identifier: Apache-2.0
"""The HTTPS fetch the known-exploited sources share (CISA's feed and its
mirrors, ENISA's dump).

Redirects are followed to https:// only, the body is read under a size cap
and a total deadline, and a source that supports validators is asked with
them (If-None-Match, If-Modified-Since): an unchanged feed costs a 304
instead of a download.
"""
from __future__ import annotations

import http.client
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from boxmunge.http_read import ReadDeadline, read_within

# The catalog was ~1.8 MB in November 2026; anything past this is not it.
KEV_MAX_BYTES = 16 * 1024 * 1024
FETCH_TIMEOUT = 30  # each read of the socket
# The whole download: a source trickling a byte inside every read timeout
# must not hold the nightly scan until its unit's timeout kills it.
KEV_FETCH_DEADLINE = 300


class ResponseTooLarge(Exception):
    """The response body is larger than KEV_MAX_BYTES."""


@dataclass(frozen=True)
class Downloaded:
    """A body, and the validators the source gave for it."""
    body: bytes
    etag: str | None
    last_modified: str | None


@dataclass(frozen=True)
class NotModified:
    """The source says the copy the validators describe is current."""


@dataclass(frozen=True)
class SourceResult:
    """What a refresh of one source did: ``updated``, ``unchanged`` (the
    source said the cache is current), ``disabled`` (the operator turned it
    off) or ``failed`` (``error`` says why; the cache is untouched)."""
    source: str
    status: str
    error: str | None = None

    @property
    def failed(self) -> bool:
        return self.status == "failed"


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to another https:// URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise urllib.error.HTTPError(
                newurl, code, f"redirect to non-https URL {newurl} refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnlyRedirects)


def _open(req: urllib.request.Request) -> Any:
    return _OPENER.open(req, timeout=FETCH_TIMEOUT)


def download(url: str, *, etag: str | None = None,
             last_modified: str | None = None) -> Downloaded | NotModified:
    """GET ``url``; NotModified if it answers 304 to the validators given."""
    headers = {"User-Agent": "boxmunge"}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    try:
        with _open(urllib.request.Request(url, headers=headers)) as resp:
            body = read_within(resp, KEV_MAX_BYTES + 1, KEV_FETCH_DEADLINE)
            got = resp.headers
    except urllib.error.HTTPError as e:
        if e.code == 304 and (etag or last_modified):
            return NotModified()
        raise
    if len(body) > KEV_MAX_BYTES:
        raise ResponseTooLarge(f"response is larger than {KEV_MAX_BYTES // 2**20} MiB")
    return Downloaded(body, got.get("ETag"), got.get("Last-Modified"))


def describe(e: Exception) -> str:
    if isinstance(e, ReadDeadline):
        return str(e)
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP {e.code} {e.reason}"
    if isinstance(e, TimeoutError) or (
        isinstance(e, urllib.error.URLError) and isinstance(e.reason, TimeoutError)
    ):
        return f"timed out after {FETCH_TIMEOUT}s"
    if isinstance(e, http.client.HTTPException):
        return f"bad HTTP response: {e!r}"
    return str(e)
