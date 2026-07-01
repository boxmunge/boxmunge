# SPDX-License-Identifier: Apache-2.0
"""Tests for standalone alert-body formatter functions in _alerting_formatters.

The format_* functions are pure (no I/O), so tests here just verify the
contracts: priority level, required keywords in title/body, no exceptions.
"""
from __future__ import annotations

from datetime import datetime, timezone


def test_kev_stale_alert_is_priority_one_and_names_the_feed() -> None:
    """format_kev_stale_alert(None) must return a priority-1 Alert whose
    title references the KEV feed so the operator knows what degraded."""
    from boxmunge.cve._alerting_formatters import format_kev_stale_alert

    alert = format_kev_stale_alert(None)
    assert alert.priority == 1
    assert "KEV" in alert.title


def test_kev_stale_alert_with_fetched_at_includes_timestamp() -> None:
    """When fetched_at is provided, the body must include the ISO timestamp
    so operators can see when the feed was last successfully fetched."""
    from boxmunge.cve._alerting_formatters import format_kev_stale_alert

    ts = datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)
    alert = format_kev_stale_alert(ts)
    assert alert.priority == 1
    assert "KEV" in alert.title
    assert ts.isoformat() in alert.body


def test_kev_stale_alert_body_mentions_never_fetched_when_none() -> None:
    """When fetched_at is None, the body should indicate the feed was never
    fetched so the operator knows this is a fresh/unconfigured state."""
    from boxmunge.cve._alerting_formatters import format_kev_stale_alert

    alert = format_kev_stale_alert(None)
    assert "never fetched" in alert.body


def test_kev_stale_alert_kind() -> None:
    """The alert kind must be 'kev_stale' for correct routing/filtering."""
    from boxmunge.cve._alerting_formatters import format_kev_stale_alert

    alert = format_kev_stale_alert(None)
    assert alert.kind == "kev_stale"
