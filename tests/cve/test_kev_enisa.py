# SPDX-License-Identifier: Apache-2.0
"""ENISA EU KEV source and conditional requests. Offline: the HTTP open is
stubbed (kev_http._open)."""
from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timezone

import pytest
import yaml

from boxmunge.config import ConfigError
from boxmunge.cve import kev_http, kev_refresh
from boxmunge.cve.kev import KEV_DEFAULT_SOURCES
from boxmunge.cve.kev_config import KevConfig, kev_config
from boxmunge.cve.kev_enisa import ENISA_MIN_ENTRIES, ENISA_URL, refresh_enisa
from boxmunge.cve.kev_refresh import refresh_kev
from boxmunge.cve.exploited import ExploitedSource, load_exploited
from boxmunge.paths import BoxPaths

NOW = datetime(2026, 11, 15, 3, 0, tzinfo=timezone.utc)
_BASE = {"hostname": "box.example.com", "admin_email": "ops@example.com"}


class _Resp:
    def __init__(self, body: bytes, headers: dict | None = None) -> None:
        self._body, self.headers = body, headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read1(self, limit: int = -1) -> bytes:
        body, self._body = self._body, b""
        return body


def _dump(n: int = ENISA_MIN_ENTRIES + 50) -> bytes:
    items = [{"cveId": f"CVE-2021-{i:05d}", "sources": ["cisa_kev"], "dateAdded": "2026-01-01"}
             for i in range(n)]
    items[0]["sources"] = ["cisa_kev", "eu_kev"]
    items[1]["sources"] = ["eu_kev"]
    return json.dumps(items).encode()


def _serve(monkeypatch, *answers) -> list:
    """Answer each request in turn (bytes -> 200 with ETag/Last-Modified, an
    Exception -> raised); record the requests."""
    seen, queue = [], list(answers)

    def open_(req):
        seen.append(req)
        answer = queue.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return _Resp(answer, {"ETag": '"v1"', "Last-Modified": "Sat, 14 Nov 2026 01:00:00 GMT"})

    monkeypatch.setattr(kev_http, "_open", open_)
    return seen


def _not_modified() -> urllib.error.HTTPError:
    return urllib.error.HTTPError(ENISA_URL, 304, "Not Modified", None, None)


def _cache(paths: BoxPaths) -> dict:
    return json.loads(paths.kev_enisa.read_text())


def test_enisa_dump_parsed_and_cached(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    seen = _serve(monkeypatch, _dump())
    result = refresh_enisa(paths, KevConfig(), NOW)
    assert result.status == "updated" and not result.failed
    doc = _cache(paths)
    assert doc["fetched_at"] == NOW.isoformat()
    assert doc["etag"] == '"v1"' and doc["last_modified"] == "Sat, 14 Nov 2026 01:00:00 GMT"
    assert doc["entries"]["CVE-2021-00000"] == ["cisa_kev", "eu_kev"]
    assert doc["entries"]["CVE-2021-00001"] == ["eu_kev"]
    assert len(doc["entries"]) == ENISA_MIN_ENTRIES + 50
    assert seen[0].full_url == ENISA_URL and not seen[0].has_header("If-none-match")
    # What exploited.py reads back from it.
    index = load_exploited(paths, NOW.date())
    assert index.lookup("CVE-2021-00001") == {ExploitedSource.EU}
    assert ExploitedSource.EU not in index.stale


@pytest.mark.parametrize("body, match", [
    (_dump(ENISA_MIN_ENTRIES - 1), "below the floor"),
    (b"<html>oops</html>", "not JSON"),
    (b'{"cveId": "CVE-1"}', "not a JSON list"),
    (json.dumps([{"cveId": "CVE-1", "sources": ["eu_kev"]}]).encode(), "no 'dateAdded'"),
    (json.dumps([{"cveId": "CVE-1", "sources": "eu_kev", "dateAdded": "x"}]).encode(),
     "no 'sources' list"),
    (json.dumps([{"sources": [], "dateAdded": "x"}]).encode(), "no 'cveId'"),
    (json.dumps(["CVE-1"]).encode(), "not an object"),
])
def test_enisa_rejects_short_or_malformed_dump(tmp_path, monkeypatch, body, match):
    paths = BoxPaths(root=tmp_path)
    _serve(monkeypatch, _dump(), body)
    refresh_enisa(paths, KevConfig(), NOW)
    before = paths.kev_enisa.read_text()
    result = refresh_enisa(paths, KevConfig(), NOW)
    assert result.failed and match in result.error
    assert paths.kev_enisa.read_text() == before  # the good cache is kept


def test_an_unreachable_enisa_is_a_failed_result_not_an_exception(tmp_path, monkeypatch):
    _serve(monkeypatch, urllib.error.HTTPError(ENISA_URL, 503, "Unavailable", None, None))
    result = refresh_enisa(BoxPaths(root=tmp_path), KevConfig(), NOW)
    assert result.failed and "HTTP 503" in result.error


def test_not_modified_keeps_cache_and_bumps_fetched_at(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    seen = _serve(monkeypatch, _dump(), _not_modified())
    refresh_enisa(paths, KevConfig(), NOW)
    first = _cache(paths)
    later = datetime(2026, 11, 16, 3, 0, tzinfo=timezone.utc)
    result = refresh_enisa(paths, KevConfig(), later)
    assert result.status == "unchanged"
    assert seen[1].get_header("If-none-match") == '"v1"'
    assert seen[1].get_header("If-modified-since") == "Sat, 14 Nov 2026 01:00:00 GMT"
    assert _cache(paths) == {**first, "fetched_at": later.isoformat()}


def test_enisa_disabled_in_config_is_not_fetched(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    seen = _serve(monkeypatch)
    result = refresh_enisa(paths, KevConfig(enisa_enabled=False), NOW)
    assert result.status == "disabled" and seen == [] and not paths.kev_enisa.exists()


def test_enisa_failure_never_blocks_the_cisa_refresh(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    paths.config_file.parent.mkdir(parents=True)
    paths.config_file.write_text(yaml.safe_dump({**_BASE}))
    cisa = {"dateReleased": datetime.now(timezone.utc).isoformat(),
            "vulnerabilities": [{"cveID": f"CVE-2020-{i:05d}"} for i in range(1400)]}
    answers = {KEV_DEFAULT_SOURCES[0]: json.dumps(cisa).encode(),
               ENISA_URL: urllib.error.URLError("no route")}

    def open_(req):
        answer = answers[req.full_url]
        if isinstance(answer, Exception):
            raise answer
        return _Resp(answer)

    monkeypatch.setattr(kev_http, "_open", open_)
    monkeypatch.setattr(kev_refresh, "refresh_enisa", refresh_enisa)  # undo the fleet-wide stub
    result = refresh_kev(paths)
    assert result.updated and result.source == KEV_DEFAULT_SOURCES[0]
    assert result.enisa.failed and "no route" in result.enisa.error


# ---------- the kev: block ----------

def _config(paths: BoxPaths, kev: dict) -> None:
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(yaml.safe_dump({**_BASE, "kev": kev}))


def test_kev_block_accepts_enisa_and_vulncheck(tmp_path):
    paths = BoxPaths(root=tmp_path)
    _config(paths, {"sources": [KEV_DEFAULT_SOURCES[0]], "enisa": {"enabled": False},
                    "vulncheck": {"token": "tok"}})
    assert kev_config(paths) == KevConfig((KEV_DEFAULT_SOURCES[0],), False, "tok")


def test_enisa_is_on_and_vulncheck_off_unless_configured(tmp_path):
    paths = BoxPaths(root=tmp_path)
    _config(paths, {"sources": [KEV_DEFAULT_SOURCES[0]]})
    config = kev_config(paths)
    assert config.enisa_enabled and config.vulncheck_token is None


def test_unknown_kev_key_still_refused(tmp_path):
    paths = BoxPaths(root=tmp_path)
    _config(paths, {"sources": [KEV_DEFAULT_SOURCES[0]], "epss": {"enabled": True}})
    with pytest.raises(ConfigError, match="only 'sources'"):
        kev_config(paths)


@pytest.mark.parametrize("extra, match", [
    ({"enisa": True}, "'kev.enisa'"),
    ({"enisa": {"enabled": "yes"}}, "'kev.enisa'"),
    ({"enisa": {"enabled": True, "x": 1}}, "'kev.enisa'"),
    ({"vulncheck": {"token": ""}}, "'kev.vulncheck'"),
    ({"vulncheck": {"token": 7}}, "'kev.vulncheck'"),
    ({"vulncheck": "tok"}, "'kev.vulncheck'"),
    ({"vulncheck": {"token": "t", "y": 1}}, "'kev.vulncheck'"),
])
def test_bad_enisa_or_vulncheck_settings_are_refused(tmp_path, extra, match):
    paths = BoxPaths(root=tmp_path)
    _config(paths, {"sources": [KEV_DEFAULT_SOURCES[0]], **extra})
    with pytest.raises(ConfigError, match=match):
        kev_config(paths)


def test_a_kev_block_without_sources_is_still_refused(tmp_path):
    paths = BoxPaths(root=tmp_path)
    _config(paths, {"enisa": {"enabled": False}})
    with pytest.raises(ConfigError, match="'sources' \\(required\\)"):
        kev_config(paths)
