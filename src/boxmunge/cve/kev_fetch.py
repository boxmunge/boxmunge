# SPDX-License-Identifier: Apache-2.0
"""Download one KEV source over https, conditionally when the cached catalog
came from it.

The catalog is ~1.8 MB and changes a few times a week, while the scan asks
every night. The source that served the cache is asked with the validators
it gave (ETag, Last-Modified); a 304 Not Modified means the catalog has not
changed since it was cached, which kev_refresh records as that source
answering. Judging the catalog (kev_refresh) is unchanged: a 304 vouches for
exactly the catalog that was judged when it was cached.
"""
from __future__ import annotations

import http.client
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

_FETCH_TIMEOUT = 30


@dataclass(frozen=True)
class Validators:
    """What a source said identifies the catalog it served."""

    etag: str | None = None
    last_modified: str | None = None

    def conditional_headers(self) -> dict[str, str]:
        headers = {}
        if self.etag:
            headers["If-None-Match"] = self.etag
        if self.last_modified:
            headers["If-Modified-Since"] = self.last_modified
        return headers


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to another https:// URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise urllib.error.HTTPError(
                newurl, code, f"redirect to non-https URL {newurl} refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnlyRedirects)


def _open(req: urllib.request.Request) -> Any:
    return _OPENER.open(req, timeout=_FETCH_TIMEOUT)


def download(url: str, limit: int, since: Validators | None) -> tuple[bytes, Validators] | None:
    """The body (at most ``limit`` + 1 bytes, so the caller sees an oversize
    one) and its validators; None when the source answered 304 to ``since``.

    Raises OSError (HTTPError, URLError, socket errors) or
    http.client.HTTPException."""
    headers = {"User-Agent": "boxmunge", **(since.conditional_headers() if since else {})}
    try:
        with _open(urllib.request.Request(url, headers=headers)) as resp:
            body = resp.read(limit + 1)
            got = Validators(resp.headers.get("ETag"), resp.headers.get("Last-Modified"))
    except urllib.error.HTTPError as e:
        if e.code == 304 and since is not None:
            return None
        raise
    return body, got


def describe(e: Exception) -> str:
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP {e.code} {e.reason}"
    if isinstance(e, TimeoutError) or (
        isinstance(e, urllib.error.URLError) and isinstance(e.reason, TimeoutError)
    ):
        return f"timed out after {_FETCH_TIMEOUT}s"
    if isinstance(e, http.client.HTTPException):
        return f"bad HTTP response: {e!r}"
    return str(e)
