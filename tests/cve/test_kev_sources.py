# SPDX-License-Identifier: Apache-2.0
"""The KEV catalog comes from an ordered list of sources (issue #121).

Offline: urlopen is stubbed per URL.
"""
from __future__ import annotations

import json
import urllib.error
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from boxmunge import http_read
from boxmunge.commands import security_actions, security_kev, security_scan_core
from boxmunge.config import ConfigError, load_config
from boxmunge.cve import kev_refresh
from boxmunge.cve.kev import KEV_DEFAULT_SOURCES, load_kev
from boxmunge.cve.kev_refresh import (
    CONFIG, REJECTED, UNREACHABLE, kev_sources, refresh_from, refresh_kev,
)
from boxmunge.paths import BoxPaths
from tests.test_commands.cve_helpers import Docker, Pushover, make_box, scan_result

CISA, MIRROR = KEV_DEFAULT_SOURCES
RECENT = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()


class _Resp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read1(self, limit: int = -1) -> bytes:
        body, self._body = self._body, b""
        return body


def _ids(n: int) -> list[str]:
    return [f"CVE-2020-{i:05d}" for i in range(n)]


def _feed(n: int = 1400, released: str = RECENT) -> bytes:
    return json.dumps({"dateReleased": released,
                       "vulnerabilities": [{"cveID": c} for c in _ids(n)]}).encode()


def _forbidden(url: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, 403, "Forbidden", None, None)


def _serve(monkeypatch, answers: dict) -> list[str]:
    """Answer each URL with bytes or raise the given exception; record calls."""
    calls: list[str] = []

    def open_(req):
        calls.append(req.full_url)
        answer = answers[req.full_url]
        if isinstance(answer, Exception):
            raise answer
        return _Resp(answer)

    monkeypatch.setattr(kev_refresh, "_open", open_)
    return calls


def _seed(paths: BoxPaths, n: int, released: str = "2026-01-01T00:00:00+00:00") -> None:
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(json.dumps({
        "source": CISA, "released_at": released,
        "fetched_at": "2026-01-01T00:00:00+00:00", "cve_ids": _ids(n)}))


def test_first_source_403_falls_through_to_the_mirror_and_records_it(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    calls = _serve(monkeypatch, {CISA: _forbidden(CISA), MIRROR: _feed()})
    result = refresh_from(paths, (CISA, MIRROR))
    assert calls == [CISA, MIRROR]
    assert result.source == MIRROR and not result.needs_alert
    assert [(f.source, f.kind, f.error) for f in result.failures] == [
        (CISA, UNREACHABLE, "HTTP 403 Forbidden")]
    cat = load_kev(paths)
    assert cat.source == MIRROR
    assert len(cat.cve_ids) == 1400
    assert not cat.is_stale(datetime.now(timezone.utc).date())


def test_first_source_answering_stops_the_list(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    calls = _serve(monkeypatch, {CISA: _feed(), MIRROR: _forbidden(MIRROR)})
    assert refresh_from(paths, (CISA, MIRROR)).source == CISA
    assert calls == [CISA]
    assert load_kev(paths).source == CISA


def test_sanity_checks_apply_to_each_source(tmp_path, monkeypatch):
    """A truncated catalog from one source is rejected and the next tried;
    the floor and the removal limit hold for the mirror too."""
    paths = BoxPaths(root=tmp_path)
    _seed(paths, 1400)
    _serve(monkeypatch, {CISA: _feed(1200), MIRROR: _feed(1400)})
    result = refresh_from(paths, (CISA, MIRROR))
    assert result.source == MIRROR
    assert result.failures[0].kind == REJECTED
    assert "200 cached CVEs are missing" in result.failures[0].error

    _serve(monkeypatch, {CISA: _forbidden(CISA), MIRROR: _feed(10)})
    result = refresh_from(paths, (CISA, MIRROR))
    assert result.source is None and result.needs_alert
    assert "below the floor" in result.failures[1].error
    assert load_kev(paths).source == MIRROR  # the earlier good catalog is kept


def test_a_lagging_mirror_cannot_roll_the_catalog_back(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _seed(paths, 1400, released="2026-11-06T19:44:45+00:00")
    _serve(monkeypatch, {CISA: _forbidden(CISA),
                         MIRROR: _feed(released="2026-11-01T00:00:00Z")})
    result = refresh_from(paths, (CISA, MIRROR))
    assert result.source is None and not result.needs_alert  # cache still fresh enough
    assert "older than the cached one" in result.failures[1].error
    assert load_kev(paths).released_at.isoformat() == "2026-11-06T19:44:45+00:00"


def test_timeouts_and_non_json_answers_are_named(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _serve(monkeypatch, {CISA: urllib.error.URLError(TimeoutError("timed out")),
                         MIRROR: b"<html>blocked</html>"})
    result = refresh_from(paths, (CISA, MIRROR))
    assert result.failures[0].error == "timed out after 30s"
    assert result.failures[1].error.startswith("response is not JSON")
    assert not result.needs_alert  # nothing answered: the staleness alert covers it


def test_a_source_that_trickles_is_cut_off_at_the_deadline(tmp_path, monkeypatch):
    """The socket timeout bounds each read, not the whole download: a source
    sending a byte inside every timeout would hold the nightly scan until its
    unit's timeout killed it, and every project not yet scanned with it."""
    paths = BoxPaths(root=tmp_path)
    now = [0.0]
    monkeypatch.setattr(http_read.time, "monotonic", lambda: now[0])

    class Trickle(_Resp):
        def read1(self, limit: int = -1) -> bytes:
            now[0] += 29
            return b"{"

    monkeypatch.setattr(kev_refresh, "_open", lambda req: Trickle(b""))
    result = refresh_from(paths, (CISA,))
    assert result.failures[0].kind == "unreachable"
    assert result.failures[0].error == (
        f"the response did not finish within {kev_refresh.KEV_FETCH_DEADLINE}s")
    assert now[0] <= kev_refresh.KEV_FETCH_DEADLINE + 29


# ---------- configuration ----------

_BASE = {"hostname": "box.example.com", "admin_email": "ops@example.com"}


def _config(paths: BoxPaths, **extra) -> None:
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(yaml.safe_dump({**_BASE, **extra}))


def test_default_sources_are_cisa_then_its_github_mirror(tmp_path):
    paths = BoxPaths(root=tmp_path)
    _config(paths)
    assert kev_sources(paths) == KEV_DEFAULT_SOURCES
    assert CISA.startswith("https://www.cisa.gov/")
    assert MIRROR.startswith("https://raw.githubusercontent.com/cisagov/kev-data/")


def test_configured_sources_replace_the_defaults(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    own = "https://kev.internal.example/kev.json"
    _config(paths, kev={"sources": [own]})
    calls = _serve(monkeypatch, {own: _feed()})
    assert refresh_kev(paths).source == own
    assert calls == [own]


@pytest.mark.parametrize("block, match", [
    ("not-a-mapping", "'kev' .* must be a mapping"),
    ({"source": [CISA]}, "only 'sources'"),
    ({"sources": []}, "non-empty list"),
    ({"sources": CISA}, "non-empty list"),
    ({"sources": ["http://www.cisa.gov/kev.json"]}, "https://"),
])
def test_bad_kev_config_fails_only_the_kev_refresh(tmp_path, block, match):
    paths = BoxPaths(root=tmp_path)
    _config(paths, kev=block)
    load_config(paths)  # every other config reader is unaffected
    with pytest.raises(ConfigError, match=match):
        kev_sources(paths)
    failure = refresh_kev(paths).failures[0]
    assert failure.kind == CONFIG and failure.source == "boxmunge.yml"


def test_unreadable_config_is_a_refresh_failure_that_alerts(tmp_path):
    paths = BoxPaths(root=tmp_path)  # no boxmunge.yml
    result = refresh_kev(paths)
    assert result.failures[0].kind == CONFIG and result.needs_alert
    assert "Config file not found" in result.failures[0].error


def test_template_documents_the_kev_sources():
    template = Path(__file__).resolve().parents[2] / "config" / "boxmunge.yml.template"
    text = template.read_text()
    assert "kev:" in text and CISA in text and MIRROR in text


# ---------- the fleet scan's alert ----------


def _scan(monkeypatch, tmp_path) -> list:
    paths = make_box(tmp_path)
    Pushover(monkeypatch, paths)  # writes boxmunge.yml
    monkeypatch.setattr(security_kev, "refresh_kev", refresh_kev)
    monkeypatch.setattr(security_kev, "load_kev", load_kev)
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    monkeypatch.setattr(security_scan_core, "scan_image", lambda r, timeout: scan_result(r))
    sent: list = []
    monkeypatch.setattr(security_kev, "send_alerts", lambda a, p: sent.extend(a))
    assert security_actions.cmd_security_scan([], paths) == 0
    return [a for a in sent if a.kind.startswith("kev_")]


def test_both_sources_failing_names_each_error_in_the_stale_alert(tmp_path, monkeypatch):
    _serve(monkeypatch, {CISA: _forbidden(CISA),
                         MIRROR: urllib.error.URLError(TimeoutError("timed out"))})
    alerts = _scan(monkeypatch, tmp_path)
    assert len(alerts) == 1
    body = alerts[0].body
    assert "stale" in alerts[0].title
    assert "Why: no KEV catalog has been fetched yet." in body
    assert f"- {CISA}: HTTP 403 Forbidden" in body
    assert f"- {MIRROR}: timed out after 30s" in body


def test_mirror_answering_for_a_blocked_cisa_raises_no_alert(tmp_path, monkeypatch):
    _serve(monkeypatch, {CISA: _forbidden(CISA), MIRROR: _feed()})
    assert _scan(monkeypatch, tmp_path) == []


def test_a_lagging_mirror_alerts_with_its_release_date(tmp_path, monkeypatch):
    """The mirror answers, so the fetch is fresh, but its catalog was
    released over the limit ago: the alert says the catalog is lagging."""
    old = (datetime.now(timezone.utc) - timedelta(days=30)).replace(microsecond=0)
    _serve(monkeypatch, {CISA: _forbidden(CISA), MIRROR: _feed(released=old.isoformat())})
    alerts = _scan(monkeypatch, tmp_path)
    assert len(alerts) == 1
    body = alerts[0].body
    assert "the catalog is lagging" in body
    assert f"{MIRROR} last served a catalog released {old:%Y-%m-%d %H:%M} UTC" in body
    assert f"- {MIRROR}: answered" in body
    assert load_kev(BoxPaths(root=tmp_path)).is_stale(date.today()) is True


def test_a_bad_kev_sources_setting_still_delivers_its_alert(tmp_path, monkeypatch):
    """A typo in kev.sources fails only the KEV refresh: Pushover still reads
    the config, so the alert naming the mistake reaches the operator."""
    paths = make_box(tmp_path)
    pushover = Pushover(monkeypatch, paths)
    config = yaml.safe_load(paths.config_file.read_text())
    paths.config_file.write_text(yaml.safe_dump({**config, "kev": {"sources": ["http://x"]}}))
    Docker(monkeypatch)
    monkeypatch.setattr(security_kev, "refresh_kev", refresh_kev)
    monkeypatch.setattr(security_kev, "load_kev", load_kev)
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    monkeypatch.setattr(security_scan_core, "scan_image", lambda r, timeout: scan_result(r))
    assert security_actions.cmd_security_scan([], paths) == 0
    kev = [(t, b) for t, b, _ in pushover.sent if "KEV" in t]
    assert len(kev) == 1
    assert "'kev.sources'" in kev[0][1] and "must hold https:// URLs" in kev[0][1]


def test_a_few_withdrawn_cves_send_a_normal_notice(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(json.dumps({
        "source": CISA, "released_at": RECENT, "fetched_at": RECENT,
        "cve_ids": _ids(1400) + ["CVE-2026-0001", "CVE-2026-0002"]}))
    _serve(monkeypatch, {CISA: _feed()})
    alerts = _scan(monkeypatch, tmp_path)
    assert [(a.kind, a.priority) for a in alerts] == [("kev_withdrawn", 0)]
    assert "- CVE-2026-0001" in alerts[0].body and "- CVE-2026-0002" in alerts[0].body
    assert CISA in alerts[0].body


def test_a_lower_ranked_source_cannot_lock_out_cisa_by_leapfrogging(tmp_path, monkeypatch):
    """After one CISA timeout, a mirror stamping a near-future date gets
    cached. CISA's genuine, older-dated catalog must still be accepted, not
    classed as lagging, or CISA is bypassed for good."""
    paths = BoxPaths(root=tmp_path)
    ahead = (datetime.now(timezone.utc) + timedelta(minutes=50)).isoformat()
    _serve(monkeypatch, {CISA: urllib.error.URLError(TimeoutError("timed out")),
                         MIRROR: _feed(released=ahead)})
    assert refresh_from(paths, (CISA, MIRROR)).source == MIRROR

    _serve(monkeypatch, {CISA: _feed(released=RECENT), MIRROR: _feed(released=ahead)})
    result = refresh_from(paths, (CISA, MIRROR))
    assert result.source == CISA and result.failures == ()
    cat = load_kev(paths)
    assert cat.source == CISA and cat.released_at.isoformat() == RECENT

    # The mirror, ranked below the cache's source, is held to its date again.
    _serve(monkeypatch, {CISA: _forbidden(CISA),
                         MIRROR: _feed(released="2026-01-01T00:00:00Z")})
    result = refresh_from(paths, (CISA, MIRROR))
    assert result.source is None and result.failures[1].kind == "lagging"


def test_a_cache_from_an_unlisted_source_does_not_hold_the_list(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(json.dumps({
        "source": "https://old-mirror.example/kev.json", "released_at": RECENT,
        "fetched_at": RECENT, "cve_ids": _ids(1400)}))
    _serve(monkeypatch, {CISA: _feed(released="2026-01-01T00:00:00Z")})
    assert refresh_from(paths, (CISA,)).source == CISA


@pytest.mark.parametrize("released, accepted", [
    (timedelta(minutes=50), True), (timedelta(hours=2), False), (timedelta(hours=23), False),
])
def test_a_release_date_over_an_hour_ahead_is_rejected(tmp_path, monkeypatch, released, accepted):
    paths = BoxPaths(root=tmp_path)
    stamp = (datetime.now(timezone.utc) + released).isoformat()
    _serve(monkeypatch, {CISA: _feed(released=stamp)})
    result = refresh_from(paths, (CISA,))
    assert result.updated is accepted
    if not accepted:
        assert "is in the future" in result.failures[0].error


def test_an_out_of_range_release_date_is_rejected_and_the_next_source_tried(
        tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _serve(monkeypatch, {CISA: _feed(released="0001-01-01T00:00:00+14:00"), MIRROR: _feed()})
    result = refresh_from(paths, (CISA, MIRROR))
    assert result.source == MIRROR
    assert result.failures[0].kind == REJECTED
    assert "is not a timestamp" in result.failures[0].error


def test_stale_with_every_source_lagging_says_they_answered(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    old = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(json.dumps({
        "source": CISA, "released_at": RECENT, "fetched_at": old, "cve_ids": _ids(1400)}))
    older = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    _serve(monkeypatch, {CISA: _feed(released=older), MIRROR: _feed(released=older)})
    [alert] = _scan(monkeypatch, tmp_path)
    assert "no KEV catalog has been accepted for 10 days" in alert.body
    assert "every source answered this run, but with a catalog older than the cached one" \
        in alert.body
    assert "no KEV source has answered" not in alert.body
