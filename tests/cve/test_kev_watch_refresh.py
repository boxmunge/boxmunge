# SPDX-License-Identifier: Apache-2.0
"""The KEV watch's refresh leaves two things to the nightly scan: the
degraded-catalog alert and the count of runs a source was passed over."""
from __future__ import annotations

import urllib.error
from datetime import timedelta

from boxmunge.commands.security_kev import refresh_kev_and_alert
from boxmunge.cve import kev_http
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.kev_refresh import refresh_from, refresh_kev as real_refresh_kev
from boxmunge.cve.kev_source_history import load_history
from boxmunge.paths import BoxPaths
from tests.cve.test_kev_disagreement import (
    CISA, NOW, OWN, SOURCES, _cache_from_cisa, _feed, _ids, _serve, LAGGED_AT, CACHED_AT, NEW,
)
from tests.test_commands.cve_helpers import Pushover, make_box


def _lagging(paths, monkeypatch) -> None:
    _cache_from_cisa(paths)
    _serve(monkeypatch, {OWN: _feed(_ids(), LAGGED_AT), CISA: urllib.error.HTTPError(
        CISA, 403, "Forbidden", None, None)})


def test_a_watch_refresh_does_not_count_a_passed_over_source(tmp_path, monkeypatch) -> None:
    paths = BoxPaths(root=tmp_path)
    _lagging(paths, monkeypatch)
    refresh_from(paths, SOURCES, nightly=False)
    assert load_history(paths)[OWN].disagreed_runs == 0
    refresh_from(paths, SOURCES)
    assert load_history(paths)[OWN].disagreed_runs == 1


def test_a_watch_refresh_with_every_source_down_sends_no_degraded_alert(
        tmp_path, monkeypatch) -> None:
    paths = make_box(tmp_path)
    pushover = Pushover(monkeypatch, paths)

    def down(req):
        raise urllib.error.URLError("unreachable")

    monkeypatch.setattr(kev_http, "_open", down)
    monkeypatch.setattr("boxmunge.commands.security_kev.refresh_kev", real_refresh_kev)
    old = NOW - timedelta(days=30)
    monkeypatch.setattr("boxmunge.commands.security_kev.load_kev", lambda p: KevCatalog(
        frozenset(_ids()), old, old, CISA))
    refresh_kev_and_alert(paths, NOW, nightly=False)
    assert pushover.sent == []
    refresh_kev_and_alert(paths, NOW)  # the nightly refresh still alerts
    assert pushover.sent


def test_a_persistent_disagreement_is_noticed_nightly_and_never_by_the_watch(
        tmp_path, monkeypatch) -> None:
    import yaml
    paths = make_box(tmp_path)
    pushover = Pushover(monkeypatch, paths)
    paths.config_file.write_text(yaml.safe_dump({
        "hostname": "box.example.com", "admin_email": "ops@example.com",
        "pushover": {"user_key": "u", "app_token": "t"}, "kev": {"sources": list(SOURCES)}}))
    _cache_from_cisa(paths)
    _serve(monkeypatch, {OWN: _feed(_ids(), LAGGED_AT), CISA: _feed(_ids() + NEW, CACHED_AT)})
    monkeypatch.setattr("boxmunge.commands.security_kev.refresh_kev", real_refresh_kev)
    monkeypatch.setattr("boxmunge.commands.security_kev.load_kev", lambda p: KevCatalog(
        frozenset(_ids()), NOW, NOW, CISA))
    for _ in range(4):
        refresh_kev_and_alert(paths, NOW, nightly=False)
    assert pushover.sent == []
    assert load_history(paths)[OWN].disagreed_runs == 0
    refresh_kev_and_alert(paths, NOW)
    assert len(pushover.sent) == 1
