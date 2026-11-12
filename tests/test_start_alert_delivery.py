"""A refused start's alert counts as sent only when it was delivered.

Real state files and the real notify; only Pushover's HTTP call is stood in
for, so the delivery result is the one notify reports.
"""
from __future__ import annotations

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
