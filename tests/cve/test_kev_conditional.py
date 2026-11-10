# SPDX-License-Identifier: Apache-2.0
"""The cache's own KEV source is asked conditionally (deep review E-5): a
304 Not Modified is that source answering with the cached catalog."""
from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timedelta, timezone

from boxmunge.cve import kev_fetch
from boxmunge.cve.kev import KEV_DEFAULT_SOURCES, load_kev
from boxmunge.cve.kev_fetch import Validators
from boxmunge.cve.kev_refresh import UNREACHABLE, refresh_from
from boxmunge.paths import BoxPaths

CISA, MIRROR = KEV_DEFAULT_SOURCES
ETAG, MODIFIED = '"kev-1"', "Mon, 09 Nov 2026 12:00:00 GMT"
_IDS = [f"CVE-2020-{i:05d}" for i in range(1400)]


class _Resp:
    def __init__(self, body: bytes, headers: dict[str, str]) -> None:
        self._body, self.headers = body, headers

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, limit: int = -1) -> bytes:
        return self._body


def _feed(released: datetime) -> bytes:
    return json.dumps({"dateReleased": released.isoformat(),
                       "vulnerabilities": [{"cveID": c} for c in _IDS]}).encode()


def _not_modified(url: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, 304, "Not Modified", None, None)


def _serve(monkeypatch, answers: dict) -> list[tuple[str, str | None, str | None]]:
    """Answer each URL; record (url, If-None-Match, If-Modified-Since)."""
    asked: list[tuple[str, str | None, str | None]] = []

    def open_(req):
        asked.append((req.full_url, req.get_header("If-none-match"),
                      req.get_header("If-modified-since")))
        answer = answers[req.full_url]
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(kev_fetch, "_open", open_)
    return asked


def _seed(paths: BoxPaths, source: str, released: datetime, fetched: datetime) -> None:
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(json.dumps({
        "source": source, "released_at": released.isoformat(),
        "fetched_at": fetched.isoformat(), "etag": ETAG, "last_modified": MODIFIED,
        "cve_ids": _IDS}))


def test_the_validators_a_source_gives_are_cached(tmp_path, monkeypatch) -> None:
    paths = BoxPaths(root=tmp_path)
    now = datetime.now(timezone.utc)
    asked = _serve(monkeypatch, {CISA: _Resp(_feed(now), {"ETag": ETAG,
                                                          "Last-Modified": MODIFIED})})
    assert refresh_from(paths, (CISA, MIRROR)).source == CISA
    assert asked == [(CISA, None, None)]  # nothing cached to compare against
    assert load_kev(paths).validators == Validators(ETAG, MODIFIED)


def test_a_304_from_the_caches_source_is_an_answer(tmp_path, monkeypatch) -> None:
    paths = BoxPaths(root=tmp_path)
    now = datetime.now(timezone.utc)
    _seed(paths, CISA, released=now - timedelta(days=2), fetched=now - timedelta(days=5))
    asked = _serve(monkeypatch, {CISA: _not_modified(CISA)})
    result = refresh_from(paths, (CISA, MIRROR))
    assert asked == [(CISA, ETAG, MODIFIED)]
    assert result.source == CISA and not result.failures and not result.withdrawn
    cat = load_kev(paths)
    assert cat.fetched_at is not None and now - cat.fetched_at < timedelta(minutes=1)
    assert cat.released_at == now - timedelta(days=2)
    assert cat.cve_ids == frozenset(_IDS) and cat.validators == Validators(ETAG, MODIFIED)
    assert cat.stale_reason(now.date()) is None


def test_a_source_that_stopped_publishing_still_goes_stale(tmp_path, monkeypatch) -> None:
    """A 304 moves the fetch time on, never the release date."""
    paths = BoxPaths(root=tmp_path)
    now = datetime.now(timezone.utc)
    _seed(paths, CISA, released=now - timedelta(days=30), fetched=now - timedelta(days=1))
    _serve(monkeypatch, {CISA: _not_modified(CISA)})
    assert refresh_from(paths, (CISA, MIRROR)).source == CISA
    reason = load_kev(paths).stale_reason(now.date())
    assert reason is not None and "lagging" in reason


def test_only_the_caches_source_is_asked_conditionally(tmp_path, monkeypatch) -> None:
    paths = BoxPaths(root=tmp_path)
    now = datetime.now(timezone.utc)
    _seed(paths, MIRROR, released=now - timedelta(days=1), fetched=now - timedelta(days=1))
    asked = _serve(monkeypatch, {
        CISA: urllib.error.HTTPError(CISA, 403, "Forbidden", None, None),
        MIRROR: _not_modified(MIRROR)})
    result = refresh_from(paths, (CISA, MIRROR))
    assert asked == [(CISA, None, None), (MIRROR, ETAG, MODIFIED)]
    assert result.source == MIRROR


def test_a_304_nobody_asked_for_is_a_failure(tmp_path, monkeypatch) -> None:
    paths = BoxPaths(root=tmp_path)
    _serve(monkeypatch, {CISA: _not_modified(CISA), MIRROR: _not_modified(MIRROR)})
    result = refresh_from(paths, (CISA, MIRROR))
    assert result.source is None
    assert [(f.kind, f.error) for f in result.failures] == [
        (UNREACHABLE, "HTTP 304 Not Modified")] * 2
