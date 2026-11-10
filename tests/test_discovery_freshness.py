# SPDX-License-Identifier: Apache-2.0
"""How long the version-check service has gone without a usable answer.

Discovery never installs from GitHub on an error answer (a circuit-breaker
hold would be lost), so a service that keeps failing would hold security
releases back silently. `platform-updates` health warns after 48 hours."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from boxmunge.discovery_freshness import record_discovery, stale_discovery_warning
from boxmunge.health_checks.platform_updates import check_platform_updates
from boxmunge.version import write_installed_version

T0 = datetime(2026, 11, 9, 12, tzinfo=timezone.utc)
ANSWER = {"action": "up_to_date", "source": "endpoint", "current_version": "0.11.3",
          "blocked": None}
FAIL = {"action": "error", "message": "...", "endpoint_error": "it answered HTTP 503 (x)"}
FALLBACK = {**ANSWER, "source": "github", "endpoint_error": "connection refused"}


@pytest.fixture
def box(paths):
    write_installed_version(paths, "0.11.3", "abc1234")
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n")
    return paths


def test_nothing_recorded_is_no_warning(box):
    assert stale_discovery_warning(box, now=T0) is None


def test_a_usable_answer_clears_the_failure(box):
    record_discovery(box, FAIL, now=T0)
    record_discovery(box, ANSWER, now=T0 + timedelta(hours=1))
    assert stale_discovery_warning(box, now=T0 + timedelta(days=5)) is None


def test_failures_within_48_hours_are_quiet(box):
    record_discovery(box, FAIL, now=T0)
    record_discovery(box, FAIL, now=T0 + timedelta(hours=47))
    assert stale_discovery_warning(box, now=T0 + timedelta(hours=47)) is None


@pytest.mark.parametrize("result,needle", [(FAIL, "HTTP 503"),
                                           (FALLBACK, "connection refused")])
def test_failing_for_over_48_hours_warns_naming_the_error(box, result, needle):
    record_discovery(box, ANSWER, now=T0 - timedelta(days=1))
    record_discovery(box, result, now=T0)
    record_discovery(box, result, now=T0 + timedelta(hours=49))
    warning = stale_discovery_warning(box, now=T0 + timedelta(hours=49))
    assert warning is not None
    assert needle in warning
    assert (T0 - timedelta(days=1)).isoformat() in warning  # last usable answer


def test_an_error_not_caused_by_the_service_is_not_recorded(box):
    record_discovery(box, {"action": "error", "message": "blocklist unreadable"}, now=T0)
    assert not box.update_discovery_state.exists()


def test_health_warns_never_errors(box):
    record_discovery(box, FAIL, now=datetime.now(timezone.utc) - timedelta(days=3))
    check = check_platform_updates(box)
    assert check.status == "warn"
    assert "HTTP 503" in check.detail


def test_unreadable_state_warns_naming_the_file(box):
    box.update_discovery_state.write_text("{broken")
    check = check_platform_updates(box)
    assert check.status == "warn"
    assert "update-discovery.json" in check.detail
