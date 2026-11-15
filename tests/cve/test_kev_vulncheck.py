# SPDX-License-Identifier: Apache-2.0
"""VulnCheck KEV source (opt-in). Offline: the HTTP open is stubbed
(kev_http._open). The responses follow the example in VulnCheck's public
docs (docs.vulncheck.com), not a captured authenticated reply."""
from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timezone

import pytest
import yaml

from boxmunge.cve import kev_http, kev_refresh
from boxmunge.cve.exploited import ExploitedSource, load_exploited
from boxmunge.cve.kev import KEV_DEFAULT_SOURCES
from boxmunge.cve.kev_config import KevConfig
from boxmunge.cve.kev_refresh import refresh_kev
from boxmunge.cve.kev_vulncheck import VULNCHECK_MIN_ENTRIES, VULNCHECK_URL, refresh_vulncheck
from boxmunge.paths import BoxPaths

NOW = datetime(2026, 11, 15, 3, 0, tzinfo=timezone.utc)
TOKEN = "vulncheck_tok_s3cret"
CONFIG = KevConfig(vulncheck_token=TOKEN)


class _Resp:
    def __init__(self, body: bytes) -> None:
        self._body, self.headers = body, {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read1(self, limit: int = -1) -> bytes:
        body, self._body = self._body, b""
        return body


def _record(cve: list[str]) -> dict:
    return {"vendorProject": "PHP Group", "product": "PHP", "cve": cve,
            "vulncheck_reported_exploitation": [], "_timestamp": "2026-01-01T00:00:00Z"}


def _page(cves: list[list[str]], next_cursor: str | None = None) -> bytes:
    meta = {"index": "vulncheck-kev", "limit": 300, "total_documents": 9999}
    if next_cursor:
        meta["next_cursor"] = next_cursor
    return json.dumps({"_benchmark": 0.01, "_meta": meta,
                       "data": [_record(c) for c in cves]}).encode()


def _filler(n: int, start: int = 0) -> list[list[str]]:
    return [[f"CVE-2020-{i:05d}"] for i in range(start, start + n)]


def _serve(monkeypatch, *answers) -> list:
    seen, queue = [], list(answers)

    def open_(req):
        seen.append(req)
        answer = queue.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return _Resp(answer)

    monkeypatch.setattr(kev_http, "_open", open_)
    return seen


def test_no_token_means_not_fetched_and_no_error(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    seen = _serve(monkeypatch)
    assert refresh_vulncheck(paths, KevConfig(), NOW) is None
    assert seen == [] and not paths.kev_vulncheck.exists()


def test_vulncheck_parsed_and_cached(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    first = [["CVE-2024-4577"], ["CVE-2023-1", "CVE-2023-2"]] + _filler(VULNCHECK_MIN_ENTRIES)
    seen = _serve(monkeypatch, _page(first, "c2"), _page([["CVE-2024-4577"], ["CVE-2025-9"]]))
    result = refresh_vulncheck(paths, CONFIG, NOW)
    assert result.status == "updated" and not result.failed
    doc = json.loads(paths.kev_vulncheck.read_text())
    assert doc["fetched_at"] == NOW.isoformat()
    assert set(doc) == {"fetched_at", "entries"}
    assert doc["entries"].count("CVE-2024-4577") == 1  # de-duplicated
    assert {"CVE-2023-1", "CVE-2023-2", "CVE-2025-9"} <= set(doc["entries"])
    assert seen[0].full_url.startswith(VULNCHECK_URL) and "cursor=c2" in seen[1].full_url
    assert seen[0].get_header("Authorization") == f"Bearer {TOKEN}"
    assert TOKEN not in seen[0].full_url
    # What exploited.py reads back from it.
    index = load_exploited(paths, NOW.date())
    assert index.lookup("CVE-2025-9") == {ExploitedSource.VULNCHECK}
    assert ExploitedSource.VULNCHECK not in index.stale


@pytest.mark.parametrize("body, match", [
    (_page(_filler(VULNCHECK_MIN_ENTRIES - 1)), "below the floor"),
    (b"<html>oops</html>", "not JSON"),
    (b'["CVE-1"]', "not a JSON object"),
    (json.dumps({"data": "x"}).encode(), "no 'data' list"),
    (json.dumps({"data": [{"cve": "CVE-1"}]}).encode(), "no 'cve' list"),
])
def test_malformed_or_short_response_is_rejected_and_cache_kept(tmp_path, monkeypatch, body, match):
    paths = BoxPaths(root=tmp_path)
    _serve(monkeypatch, _page(_filler(VULNCHECK_MIN_ENTRIES)), body)
    refresh_vulncheck(paths, CONFIG, NOW)
    before = paths.kev_vulncheck.read_text()
    result = refresh_vulncheck(paths, CONFIG, NOW)
    assert result.failed and match in result.error
    assert paths.kev_vulncheck.read_text() == before


def test_vulncheck_auth_failure_reported_not_raised_into_cisa(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    paths.config_file.parent.mkdir(parents=True)
    paths.config_file.write_text(yaml.safe_dump({
        "hostname": "box.example.com", "admin_email": "ops@example.com",
        "kev": {"sources": [KEV_DEFAULT_SOURCES[0]], "vulncheck": {"token": TOKEN}}}))
    cisa = {"dateReleased": datetime.now(timezone.utc).isoformat(),
            "vulnerabilities": [{"cveID": f"CVE-2020-{i:05d}"} for i in range(1400)]}

    def open_(req):
        if req.full_url == KEV_DEFAULT_SOURCES[0]:
            return _Resp(json.dumps(cisa).encode())
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", None, None)

    monkeypatch.setattr(kev_http, "_open", open_)
    monkeypatch.setattr(kev_refresh, "refresh_vulncheck", refresh_vulncheck)  # undo the stub
    result = refresh_kev(paths)
    assert result.updated and result.source == KEV_DEFAULT_SOURCES[0]
    assert result.vulncheck.failed and "401" in result.vulncheck.error
    assert TOKEN not in result.vulncheck.error and TOKEN not in result.vulncheck.source


def test_an_endless_cursor_is_a_failure_not_a_loop(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _serve(monkeypatch, *[_page(_filler(5), "again")] * 500)
    result = refresh_vulncheck(paths, CONFIG, NOW)
    assert result.failed and "pages" in result.error


def test_doctor_says_once_vulncheck_is_off(paths, docker_down, capsys):
    from boxmunge.commands.doctor import run_doctor
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(yaml.safe_dump(
        {"hostname": "box.example.com", "admin_email": "ops@example.com"}))
    run_doctor(paths, as_json=True)
    rows = [r for r in json.loads(capsys.readouterr().out) if r["name"] == "VulnCheck KEV"]
    assert len(rows) == 1 and rows[0]["status"] == "INFO"
