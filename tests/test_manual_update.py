# SPDX-License-Identifier: Apache-2.0
"""The manual-upgrade notice: once per version, low priority, shown by health."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from boxmunge.commands.auto_update_cmd import run_auto_update
from boxmunge.health_checks.platform_updates import check_platform_updates
from boxmunge.manual_update import ManualStateError, notice_text, read_manual, record_manual
from boxmunge.version import write_installed_version

GH = "https://github.com/boxmunge/boxmunge/releases/tag/v"
T0 = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
BASE = "hostname: t\nadmin_email: a@b\n"


def _manual(version="0.12.0"):
    return {"version": version, "url": f"{GH}{version}", "class": "feature"}


def _result(manual):
    return {"action": "up_to_date", "current_version": "0.11.8", "blocked": None,
            "manual": manual, "source": "endpoint"}


@pytest.fixture
def box(paths):
    write_installed_version(paths, "0.11.8", "abc1234")
    paths.config_file.write_text(BASE)
    return paths


@pytest.fixture
def sent():
    calls: list[dict] = []
    delivered = {"ok": True}

    def fake(paths, title, body, **kwargs):
        calls.append({"title": title, "body": body, **kwargs})
        return delivered["ok"]
    fake.calls, fake.delivered = calls, delivered
    with patch("boxmunge.manual_update.notify", fake):
        yield fake


def test_notice_text_exact():
    assert notice_text("0.12.0") == (
        "0.12.0 is available and needs a manual upgrade: ask your agent to run `upgrade-howto`")


def test_alerts_once_per_version_at_priority_minus_1(box, sent):
    record_manual(box, _result(_manual()), now=T0)
    record_manual(box, _result(_manual()), now=T0)
    assert len(sent.calls) == 1
    assert sent.calls[0]["priority"] == -1
    assert notice_text("0.12.0") in sent.calls[0]["body"]
    assert read_manual(box)["version"] == "0.12.0"


def test_undelivered_alert_retries_next_run(box, sent):
    sent.delivered["ok"] = False
    record_manual(box, _result(_manual()), now=T0)
    assert read_manual(box) is None
    sent.delivered["ok"] = True
    record_manual(box, _result(_manual()), now=T0)
    assert len(sent.calls) == 2 and read_manual(box) is not None


def test_new_version_alerts_again(box, sent):
    record_manual(box, _result(_manual("0.12.0")), now=T0)
    record_manual(box, _result(_manual("0.13.0")), now=T0)
    assert [c["title"] for c in sent.calls] == [
        "0.12.0 needs a manual upgrade", "0.13.0 needs a manual upgrade"]


def test_manual_none_clears_state(box, sent):
    record_manual(box, _result(_manual()), now=T0)
    record_manual(box, _result(None), now=T0)
    assert not box.platform_manual_update.exists()
    record_manual(box, _result(None), now=T0)  # nothing to clear: fine


def test_corrupt_state_is_replaced_loudly(box, sent, capsys):
    box.platform_manual_update.write_text("{nope")
    record_manual(box, _result(_manual()), now=T0)
    assert "platform-manual-update.json" in capsys.readouterr().err
    assert len(sent.calls) == 1 and read_manual(box)["version"] == "0.12.0"


@pytest.mark.parametrize("state", [
    {"version": "0.12.0"}, {"version": "x", "alerted_at": T0.isoformat()},
    {"version": "0.12.0", "alerted_at": "yesterday"},
    {"version": "0.12.0", "alerted_at": "2026-11-01T12:00:00"}])
def test_read_manual_is_strict(box, state):
    box.platform_manual_update.write_text(json.dumps(state))
    with pytest.raises(ManualStateError):
        read_manual(box)


def test_health_ok_with_notice_in_detail(box, sent):
    record_manual(box, _result(_manual()), now=T0)
    check = check_platform_updates(box)
    assert check.status == "ok"
    assert notice_text("0.12.0") in check.detail


def test_health_drops_notice_once_installed(box, sent):
    record_manual(box, _result(_manual("0.11.8")), now=T0)
    assert "manual upgrade" not in check_platform_updates(box).detail


def test_health_keeps_a_warning_and_appends_the_notice(box, sent):
    blocked = {"version": "0.11.9", "url": f"{GH}0.11.9", "class": "security",
               "reason": {"breaking_release": "0.12.0"}}
    box.platform_update_state.write_text(json.dumps({
        "checked_at": T0.isoformat(), "current_version": "0.11.8",
        "blocked": blocked, "alerted": None}))
    record_manual(box, _result(_manual()), now=T0)
    check = check_platform_updates(box)
    assert check.status == "warn"
    assert "Security release 0.11.9" in check.detail and notice_text("0.12.0") in check.detail


def test_health_warns_on_unreadable_state(box):
    box.platform_manual_update.write_text("[]")
    check = check_platform_updates(box)
    assert check.status == "warn" and "platform-manual-update.json" in check.detail


def test_opted_out_box_records_nothing(box, sent):
    box.config_file.write_text(BASE + "version_check:\n  enabled: false\n")
    with patch("boxmunge.upgrade_discovery.discover_update") as discover:
        assert run_auto_update(box) == 0
    discover.assert_not_called()
    assert not sent.calls and not box.platform_manual_update.exists()


def test_auto_update_records_the_manual_release(box, sent):
    with patch("boxmunge.upgrade_discovery.discover_update",
               return_value=_result(_manual())):
        assert run_auto_update(box) == 0
    assert len(sent.calls) == 1 and read_manual(box)["version"] == "0.12.0"


def test_a_discovery_error_leaves_the_state_alone(box, sent):
    record_manual(box, _result(_manual()), now=T0)
    with patch("boxmunge.upgrade_discovery.discover_update",
               return_value={"action": "error", "message": "x"}):
        assert run_auto_update(box) == 1
    assert read_manual(box)["version"] == "0.12.0"
