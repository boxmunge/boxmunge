"""A refused start's alert counts as sent only when it was delivered.

Real state files and the real notify; only Pushover's HTTP call is stood in
for, so the delivery result is the one notify reports.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge import compose_guard
from boxmunge.paths import BoxPaths

NAME = "shop"
REASON = "control file manifest.yml changed"


@pytest.fixture
def box(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in (paths.config, paths.state, paths.logs):
        d.mkdir(parents=True)
    paths.config_file.write_text(yaml.safe_dump({
        "hostname": "box.example.com", "admin_email": "ops@example.com",
        "pushover": {"user_key": "u", "app_token": "t"},
    }))
    return paths


def _refuse(paths: BoxPaths, delivered: bool) -> int:
    """One refusal; how many times Pushover was tried."""
    with patch("boxmunge.notify.send_notification", return_value=delivered) as send:
        compose_guard._refused(paths, NAME, "health", REASON)
    return send.call_count


def test_an_undelivered_alert_is_retried_on_the_next_refusal(box: BoxPaths) -> None:
    """Pushover down on the first refusal: the next one tries again, and
    only its delivery starts the 24 hours of quiet."""
    assert _refuse(box, delivered=False) == 1
    assert not (box.state / "start-refused" / f"{NAME}.json").exists()

    assert _refuse(box, delivered=True) == 1
    assert (box.state / "start-refused" / f"{NAME}.json").exists()

    assert _refuse(box, delivered=False) == 0
    assert box.log_file.read_text().count(f"Refused to start {NAME}") == 3


def test_every_failed_attempt_is_tried_again(box: BoxPaths) -> None:
    assert [_refuse(box, delivered=False) for _ in range(3)] == [1, 1, 1]
    assert box.log_file.read_text().count("Pushover request failed") == 3


def test_an_unconfigured_pushover_records_nothing_as_sent(box: BoxPaths) -> None:
    """Configuring Pushover later must alert on the very next refusal."""
    config = yaml.safe_load(box.config_file.read_text())
    box.config_file.write_text(yaml.safe_dump({**config, "pushover": {}}))
    assert _refuse(box, delivered=True) == 0
    box.config_file.write_text(yaml.safe_dump(config))
    assert _refuse(box, delivered=True) == 1


def test_a_record_dated_ahead_of_now_does_not_silence_the_alert(box: BoxPaths) -> None:
    """A clock that was wrong when the alert was recorded, or an edited
    file: the time is not one this box could have written, so it is not
    believed."""
    assert _refuse(box, delivered=True) == 1
    record = box.state / "start-refused" / f"{NAME}.json"
    ahead = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    record.write_text(json.dumps({key: ahead for key in json.loads(record.read_text())}))

    assert _refuse(box, delivered=True) == 1
    assert _refuse(box, delivered=True) == 0  # recorded at the real time again


def test_a_record_that_cannot_be_written_does_not_fail_the_refusal(box: BoxPaths) -> None:
    """The alert is sent by then. The refusal is returned as ever, the
    failure is logged, and the next refusal alerts again."""
    (box.state / "start-refused" / f"{NAME}.json").mkdir(parents=True)

    for _ in range(2):
        assert _refuse(box, delivered=True) == 1
    log = box.log_file.read_text()
    assert log.count("Cannot record the alert") == 2
    assert log.count(f"Refused to start {NAME}") == 2
