# SPDX-License-Identifier: Apache-2.0
"""Tests for boxmunge.cve.grace — grace-window state I/O and predicates."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from boxmunge.cve.grace import (
    GRACE_DURATION,
    GraceError,
    GraceState,
    grace_state_path,
    init_grace_if_missing,
    mark_heads_up_sent,
    read_grace_state,
    write_grace_state,
)
from boxmunge.paths import BoxPaths


def _paths(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path)
    paths.state.mkdir(parents=True, exist_ok=True)
    return paths


def _now() -> datetime:
    return datetime(2026, 5, 6, 12, 0, 0, tzinfo=timezone.utc)


def test_grace_state_path_under_state_dir(tmp_path) -> None:
    paths = _paths(tmp_path)
    p = grace_state_path(paths)
    assert p == paths.state / "cve-grace.json"
    assert p == paths.cve_grace_state


def test_read_grace_state_missing_file_returns_none(tmp_path) -> None:
    paths = _paths(tmp_path)
    assert read_grace_state(paths) is None


def test_read_grace_state_well_formed(tmp_path) -> None:
    paths = _paths(tmp_path)
    paths.cve_grace_state.parent.mkdir(parents=True, exist_ok=True)
    paths.cve_grace_state.write_text(json.dumps({
        "installed_at": "2026-05-06T12:00:00+00:00",
        "expires_at": "2026-05-07T12:00:00+00:00",
        "heads_up_sent": False,
    }))
    state = read_grace_state(paths)
    assert state is not None
    assert state.installed_at == datetime(2026, 5, 6, 12, tzinfo=timezone.utc)
    assert state.expires_at == datetime(2026, 5, 7, 12, tzinfo=timezone.utc)
    assert state.heads_up_sent is False


def test_read_grace_state_malformed_raises_grace_error(tmp_path) -> None:
    paths = _paths(tmp_path)
    paths.cve_grace_state.parent.mkdir(parents=True, exist_ok=True)
    paths.cve_grace_state.write_text("not valid json {")
    with pytest.raises(GraceError):
        read_grace_state(paths)


def test_read_grace_state_missing_field_raises(tmp_path) -> None:
    paths = _paths(tmp_path)
    paths.cve_grace_state.parent.mkdir(parents=True, exist_ok=True)
    paths.cve_grace_state.write_text(json.dumps({
        "installed_at": "2026-05-06T12:00:00+00:00",
        # expires_at and heads_up_sent missing
    }))
    with pytest.raises(GraceError):
        read_grace_state(paths)


def test_read_grace_state_naive_timestamp_raises(tmp_path) -> None:
    paths = _paths(tmp_path)
    paths.cve_grace_state.parent.mkdir(parents=True, exist_ok=True)
    paths.cve_grace_state.write_text(json.dumps({
        "installed_at": "2026-05-06T12:00:00",
        "expires_at": "2026-05-07T12:00:00",
        "heads_up_sent": False,
    }))
    with pytest.raises(GraceError):
        read_grace_state(paths)


def test_write_grace_state_round_trip(tmp_path) -> None:
    paths = _paths(tmp_path)
    state = GraceState(
        installed_at=_now(),
        expires_at=_now() + GRACE_DURATION,
        heads_up_sent=True,
    )
    write_grace_state(paths, state)
    assert paths.cve_grace_state.exists()
    rebuilt = read_grace_state(paths)
    assert rebuilt == state


def test_init_grace_if_missing_creates_file_with_24h_expiry(tmp_path) -> None:
    paths = _paths(tmp_path)
    now = _now()
    state = init_grace_if_missing(paths, now=now)
    assert state.installed_at == now
    assert state.expires_at == now + timedelta(hours=24)
    assert state.heads_up_sent is False
    assert paths.cve_grace_state.exists()


def test_init_grace_if_missing_returns_existing_unchanged(tmp_path) -> None:
    paths = _paths(tmp_path)
    earlier = _now()
    later = _now() + timedelta(hours=12)
    first = init_grace_if_missing(paths, now=earlier)
    second = init_grace_if_missing(paths, now=later)
    assert second == first
    # Even if expired, we don't re-init.
    much_later = first.expires_at + timedelta(days=30)
    third = init_grace_if_missing(paths, now=much_later)
    assert third == first


def test_is_active_strictly_before_expires() -> None:
    expires = _now() + timedelta(hours=24)
    state = GraceState(
        installed_at=_now(),
        expires_at=expires,
        heads_up_sent=False,
    )
    assert state.is_active(now=_now()) is True
    assert state.is_active(now=expires - timedelta(seconds=1)) is True


def test_is_active_at_expires_time_is_inactive() -> None:
    expires = _now() + timedelta(hours=24)
    state = GraceState(
        installed_at=_now(),
        expires_at=expires,
        heads_up_sent=False,
    )
    # At the boundary itself, grace is over.
    assert state.is_active(now=expires) is False


def test_is_active_after_expires_is_inactive() -> None:
    expires = _now() + timedelta(hours=24)
    state = GraceState(
        installed_at=_now(),
        expires_at=expires,
        heads_up_sent=False,
    )
    assert state.is_active(now=expires + timedelta(seconds=1)) is False


def test_mark_heads_up_sent_persists(tmp_path) -> None:
    paths = _paths(tmp_path)
    state = init_grace_if_missing(paths, now=_now())
    assert state.heads_up_sent is False
    updated = mark_heads_up_sent(paths, state)
    assert updated.heads_up_sent is True
    rebuilt = read_grace_state(paths)
    assert rebuilt is not None
    assert rebuilt.heads_up_sent is True
    assert rebuilt.installed_at == state.installed_at
    assert rebuilt.expires_at == state.expires_at


# ---------- structured-extras (audit A-1) ----------


def test_init_grace_emits_structured_log(tmp_path) -> None:
    """Wave 3: grace init log carries component='cve-grace', project=None."""
    import logging as _logging
    paths = _paths(tmp_path)

    records: list = []

    class _ListHandler(_logging.Handler):
        def emit(self, record):  # type: ignore[override]
            records.append(record)

    h = _ListHandler(level=_logging.INFO)
    logger = _logging.getLogger("boxmunge")
    saved_level = logger.level
    logger.setLevel(_logging.INFO)
    logger.addHandler(h)
    try:
        init_grace_if_missing(paths, now=_now())
    finally:
        logger.removeHandler(h)
        logger.setLevel(saved_level)

    grace_records = [
        r for r in records
        if getattr(r, "component", None) == "cve-grace"
    ]
    assert len(grace_records) == 1
    rec = grace_records[0]
    assert getattr(rec, "project", "missing") is None
    detail = getattr(rec, "detail", None)
    assert isinstance(detail, dict)
    assert "installed_at" in detail
    assert "expires_at" in detail
