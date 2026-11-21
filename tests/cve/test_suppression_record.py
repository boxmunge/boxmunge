# SPDX-License-Identifier: Apache-2.0
"""cve.suppression_record: the once-only warning keys and pending host expiries."""
from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from boxmunge.cve.suppression_record import (
    NoticeRecord, host_key, read_record, record_lock, warned_key, write_record,
)
from boxmunge.cve.suppressions import SCOPE_HOST, SCOPE_PROJECT, Suppression
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

NOW = datetime(2026, 11, 21, 3, tzinfo=timezone.utc)


def _sup(until: date, scope: str) -> Suppression:
    return Suppression("CVE-2026-57433", until, "r", "ops", date(2026, 8, 25), scope=scope)


def test_keys_host_once_for_the_fleet_project_per_project() -> None:
    host, own = _sup(date(2026, 11, 23), SCOPE_HOST), _sup(date(2026, 11, 23), SCOPE_PROJECT)
    assert warned_key(host, "shop") == warned_key(host, "blog")
    assert warned_key(own, "shop") != warned_key(own, "blog")
    assert warned_key(own, "shop") != warned_key(_sup(date(2026, 11, 30), SCOPE_PROJECT), "shop")


def test_round_trip_prunes_passed_warnings_and_keeps_pending(tmp_path) -> None:
    paths = BoxPaths(root=tmp_path)
    assert read_record(paths) == NoticeRecord()
    live = warned_key(_sup(date(2026, 11, 23), SCOPE_HOST), "")
    gone = warned_key(_sup(date(2026, 11, 21), SCOPE_PROJECT), "shop")
    pending = host_key(_sup(date(2026, 11, 20), SCOPE_HOST))
    with record_lock(paths):
        write_record(paths, NoticeRecord({live: NOW, gone: NOW}, {pending}), date(2026, 11, 21))
    assert read_record(paths) == NoticeRecord({live: NOW}, {pending})


@pytest.mark.parametrize("raw", [
    "{not json", '{"warned": [{"cve_id": "x"}], "pending_host_expiries": []}',
    '{"warned": [{"cve_id": "x", "scope": "host", "project": "", "until": "soon",'
    ' "warned_at": "2026-11-21T03:00:00+00:00"}], "pending_host_expiries": []}',
    '{"warned": [], "pending_host_expiries": [{"cve_id": "x"}]}'])
def test_unusable_record_is_refused_naming_the_file(tmp_path, raw) -> None:
    paths = BoxPaths(root=tmp_path)
    paths.suppression_notices.parent.mkdir(parents=True)
    paths.suppression_notices.write_text(raw)
    with pytest.raises(StateError, match="suppression-notices.json"):
        read_record(paths)
