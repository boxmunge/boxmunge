"""Tests for boxmunge.cve.suppressions — per-project CVE suppression file I/O."""

from datetime import date
from pathlib import Path

import pytest

from boxmunge.cve.suppressions import (
    Suppression,
    SuppressionsError,
    active_suppressions,
    add_suppression,
    expired_suppressions,
    find_active_suppression,
    find_recent_removal,
    history_path_for,
    load_suppressions,
    record_removal,
    remove_suppression,
)


# ---------- helpers ----------


_VALID_ENTRY_YAML = """\
suppressions:
  - cve: CVE-2026-1234
    until: 2026-08-01
    reason: "Endpoint not exposed in our config; vulnerable code path unreachable."
    reviewed_by: jon
    added: 2026-05-06
"""


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def _make(
    cve_id: str = "CVE-2026-1234",
    until: date = date(2026, 8, 1),
    reason: str = "reviewed",
    reviewed_by: str = "jon",
    added: date = date(2026, 5, 6),
) -> Suppression:
    return Suppression(
        cve_id=cve_id,
        until=until,
        reason=reason,
        reviewed_by=reviewed_by,
        added=added,
    )


# ---------- Loading ----------


def test_load_missing_file_returns_empty(tmp_path: Path) -> None:
    path = tmp_path / "security" / "suppressions.yml"
    assert load_suppressions(path) == ()


def test_load_empty_suppressions_list(tmp_path: Path) -> None:
    path = _write(tmp_path / "suppressions.yml", "suppressions: []\n")
    assert load_suppressions(path) == ()


def test_load_well_formed_file(tmp_path: Path) -> None:
    path = _write(tmp_path / "suppressions.yml", _VALID_ENTRY_YAML)
    result = load_suppressions(path)
    assert len(result) == 1
    s = result[0]
    assert s.cve_id == "CVE-2026-1234"
    assert s.until == date(2026, 8, 1)
    assert s.reason == (
        "Endpoint not exposed in our config; vulnerable code path unreachable."
    )
    assert s.reviewed_by == "jon"
    assert s.added == date(2026, 5, 6)


def test_load_multiple_entries_sorted_by_cve_id(tmp_path: Path) -> None:
    yaml_text = """\
suppressions:
  - cve: CVE-2026-9999
    until: 2026-09-01
    reason: r1
    reviewed_by: jon
    added: 2026-05-06
  - cve: CVE-2026-1111
    until: 2026-09-01
    reason: r2
    reviewed_by: jon
    added: 2026-05-06
  - cve: CVE-2026-5555
    until: 2026-09-01
    reason: r3
    reviewed_by: jon
    added: 2026-05-06
"""
    path = _write(tmp_path / "suppressions.yml", yaml_text)
    result = load_suppressions(path)
    assert [s.cve_id for s in result] == [
        "CVE-2026-1111",
        "CVE-2026-5555",
        "CVE-2026-9999",
    ]


def test_load_malformed_yaml(tmp_path: Path) -> None:
    path = _write(tmp_path / "suppressions.yml", "suppressions: [: bad]\n")
    with pytest.raises(SuppressionsError) as ei:
        load_suppressions(path)
    # error mentions parse / yaml context
    assert "suppressions.yml" in str(ei.value) or "parse" in str(ei.value).lower() \
        or "yaml" in str(ei.value).lower()


def test_load_missing_top_level_key(tmp_path: Path) -> None:
    path = _write(tmp_path / "suppressions.yml", "foo: []\n")
    with pytest.raises(SuppressionsError) as ei:
        load_suppressions(path)
    assert "suppressions" in str(ei.value)


def test_load_top_level_not_a_mapping(tmp_path: Path) -> None:
    path = _write(tmp_path / "suppressions.yml", "- a\n- b\n")
    with pytest.raises(SuppressionsError):
        load_suppressions(path)


def test_load_suppressions_not_a_list(tmp_path: Path) -> None:
    path = _write(tmp_path / "suppressions.yml", "suppressions: notalist\n")
    with pytest.raises(SuppressionsError) as ei:
        load_suppressions(path)
    assert "list" in str(ei.value).lower()


def test_load_bad_cve_id_format(tmp_path: Path) -> None:
    yaml_text = """\
suppressions:
  - cve: notacve
    until: 2026-08-01
    reason: r
    reviewed_by: jon
    added: 2026-05-06
"""
    path = _write(tmp_path / "suppressions.yml", yaml_text)
    with pytest.raises(SuppressionsError) as ei:
        load_suppressions(path)
    msg = str(ei.value)
    assert "notacve" in msg
    assert "cve" in msg.lower()


def test_load_missing_required_field(tmp_path: Path) -> None:
    yaml_text = """\
suppressions:
  - cve: CVE-2026-1234
    until: 2026-08-01
    reviewed_by: jon
    added: 2026-05-06
"""
    path = _write(tmp_path / "suppressions.yml", yaml_text)
    with pytest.raises(SuppressionsError) as ei:
        load_suppressions(path)
    assert "reason" in str(ei.value)


def test_load_empty_reason(tmp_path: Path) -> None:
    yaml_text = """\
suppressions:
  - cve: CVE-2026-1234
    until: 2026-08-01
    reason: "   "
    reviewed_by: jon
    added: 2026-05-06
"""
    path = _write(tmp_path / "suppressions.yml", yaml_text)
    with pytest.raises(SuppressionsError) as ei:
        load_suppressions(path)
    assert "reason" in str(ei.value).lower()


def test_load_empty_reviewed_by(tmp_path: Path) -> None:
    yaml_text = """\
suppressions:
  - cve: CVE-2026-1234
    until: 2026-08-01
    reason: r
    reviewed_by: ""
    added: 2026-05-06
"""
    path = _write(tmp_path / "suppressions.yml", yaml_text)
    with pytest.raises(SuppressionsError) as ei:
        load_suppressions(path)
    assert "reviewed_by" in str(ei.value).lower()


def test_load_bad_until_format(tmp_path: Path) -> None:
    yaml_text = """\
suppressions:
  - cve: CVE-2026-1234
    until: tomorrow
    reason: r
    reviewed_by: jon
    added: 2026-05-06
"""
    path = _write(tmp_path / "suppressions.yml", yaml_text)
    with pytest.raises(SuppressionsError) as ei:
        load_suppressions(path)
    assert "until" in str(ei.value).lower()


def test_load_bad_added_format(tmp_path: Path) -> None:
    # PyYAML accepts YYYY-MM-DD natively but not YYYY/MM/DD; the latter
    # comes through as a string and must fail our ISO check.
    yaml_text = """\
suppressions:
  - cve: CVE-2026-1234
    until: 2026-08-01
    reason: r
    reviewed_by: jon
    added: "2026/05/06"
"""
    path = _write(tmp_path / "suppressions.yml", yaml_text)
    with pytest.raises(SuppressionsError) as ei:
        load_suppressions(path)
    assert "added" in str(ei.value).lower()


def test_load_entry_not_a_mapping(tmp_path: Path) -> None:
    yaml_text = """\
suppressions:
  - "just a string"
"""
    path = _write(tmp_path / "suppressions.yml", yaml_text)
    with pytest.raises(SuppressionsError) as ei:
        load_suppressions(path)
    assert "0" in str(ei.value)  # index reference


# ---------- Filtering ----------


def test_is_active_strictly_before_until() -> None:
    s = _make(until=date(2026, 8, 1))
    assert s.is_active(today=date(2026, 7, 31)) is True


def test_is_active_on_until_date_is_expired() -> None:
    s = _make(until=date(2026, 8, 1))
    assert s.is_active(today=date(2026, 8, 1)) is False


def test_is_active_after_until_is_expired() -> None:
    s = _make(until=date(2026, 8, 1))
    assert s.is_active(today=date(2026, 8, 2)) is False


def test_active_suppressions_filters() -> None:
    today = date(2026, 6, 1)
    a = _make(cve_id="CVE-2026-0001", until=date(2026, 7, 1))
    b = _make(cve_id="CVE-2026-0002", until=date(2026, 5, 1))
    c = _make(cve_id="CVE-2026-0003", until=date(2027, 1, 1))
    result = active_suppressions((a, b, c), today=today)
    assert result == (a, c)


def test_expired_suppressions_filters() -> None:
    today = date(2026, 6, 1)
    a = _make(cve_id="CVE-2026-0001", until=date(2026, 7, 1))
    b = _make(cve_id="CVE-2026-0002", until=date(2026, 5, 1))
    c = _make(cve_id="CVE-2026-0003", until=date(2027, 1, 1))
    result = expired_suppressions((a, b, c), today=today)
    assert result == (b,)


def test_find_active_suppression_match() -> None:
    today = date(2026, 6, 1)
    a = _make(cve_id="CVE-2026-0001", until=date(2026, 7, 1))
    b = _make(cve_id="CVE-2026-0002", until=date(2027, 1, 1))
    assert find_active_suppression((a, b), "CVE-2026-0002", today=today) == b


def test_find_active_suppression_no_match() -> None:
    today = date(2026, 6, 1)
    a = _make(cve_id="CVE-2026-0001", until=date(2026, 7, 1))
    assert find_active_suppression((a,), "CVE-2026-9999", today=today) is None


def test_find_active_suppression_skips_expired() -> None:
    today = date(2026, 6, 1)
    a = _make(cve_id="CVE-2026-0001", until=date(2026, 5, 1))  # expired
    assert find_active_suppression((a,), "CVE-2026-0001", today=today) is None


# ---------- Adding ----------


def test_add_creates_file_when_missing(tmp_path: Path) -> None:
    path = tmp_path / "security" / "suppressions.yml"
    s = add_suppression(
        path,
        cve_id="CVE-2026-1234",
        until=date(2026, 8, 1),
        reason="reviewed; not exploitable",
        reviewed_by="jon",
        today=date(2026, 5, 6),
    )
    assert path.exists()
    assert s.cve_id == "CVE-2026-1234"
    loaded = load_suppressions(path)
    assert loaded == (s,)


def test_add_appends_to_existing_file(tmp_path: Path) -> None:
    path = _write(tmp_path / "suppressions.yml", _VALID_ENTRY_YAML)
    s2 = add_suppression(
        path,
        cve_id="CVE-2026-9999",
        until=date(2026, 9, 1),
        reason="another",
        reviewed_by="jon",
        today=date(2026, 5, 7),
    )
    loaded = load_suppressions(path)
    assert len(loaded) == 2
    assert s2 in loaded
    assert any(x.cve_id == "CVE-2026-1234" for x in loaded)


def test_add_rejects_duplicate_cve_id(tmp_path: Path) -> None:
    path = _write(tmp_path / "suppressions.yml", _VALID_ENTRY_YAML)
    with pytest.raises(SuppressionsError) as ei:
        add_suppression(
            path,
            cve_id="CVE-2026-1234",
            until=date(2027, 1, 1),
            reason="dup",
            reviewed_by="jon",
            today=date(2026, 5, 6),
        )
    assert "CVE-2026-1234" in str(ei.value)


def test_add_rejects_duplicate_even_if_expired(tmp_path: Path) -> None:
    yaml_text = """\
suppressions:
  - cve: CVE-2026-1234
    until: 2026-01-01
    reason: r
    reviewed_by: jon
    added: 2025-12-01
"""
    path = _write(tmp_path / "suppressions.yml", yaml_text)
    with pytest.raises(SuppressionsError):
        add_suppression(
            path,
            cve_id="CVE-2026-1234",
            until=date(2027, 1, 1),
            reason="dup",
            reviewed_by="jon",
            today=date(2026, 5, 6),
        )


def test_add_rejects_invalid_input(tmp_path: Path) -> None:
    path = tmp_path / "suppressions.yml"
    with pytest.raises(SuppressionsError):
        add_suppression(
            path,
            cve_id="not-a-cve",
            until=date(2026, 8, 1),
            reason="r",
            reviewed_by="jon",
            today=date(2026, 5, 6),
        )
    # File must NOT be created on failed validation.
    assert not path.exists()


def test_add_rejects_empty_reason(tmp_path: Path) -> None:
    path = tmp_path / "suppressions.yml"
    with pytest.raises(SuppressionsError):
        add_suppression(
            path,
            cve_id="CVE-2026-1234",
            until=date(2026, 8, 1),
            reason="   ",
            reviewed_by="jon",
            today=date(2026, 5, 6),
        )
    assert not path.exists()


def test_add_sets_added_to_today(tmp_path: Path) -> None:
    path = tmp_path / "suppressions.yml"
    today = date(2026, 5, 6)
    s = add_suppression(
        path,
        cve_id="CVE-2026-1234",
        until=date(2026, 8, 1),
        reason="r",
        reviewed_by="jon",
        today=today,
    )
    assert s.added == today


def test_add_uses_atomic_write(tmp_path: Path) -> None:
    path = tmp_path / "suppressions.yml"
    add_suppression(
        path,
        cve_id="CVE-2026-1234",
        until=date(2026, 8, 1),
        reason="r",
        reviewed_by="jon",
        today=date(2026, 5, 6),
    )
    # No leftover .tmp scratch files in the parent directory.
    leftovers = [p for p in path.parent.iterdir() if p.suffix == ".tmp"]
    assert leftovers == []


# ---------- Removing ----------


def test_remove_existing_entry(tmp_path: Path) -> None:
    yaml_text = """\
suppressions:
  - cve: CVE-2026-0001
    until: 2026-08-01
    reason: r1
    reviewed_by: jon
    added: 2026-05-06
  - cve: CVE-2026-0002
    until: 2026-08-01
    reason: r2
    reviewed_by: jon
    added: 2026-05-06
"""
    path = _write(tmp_path / "suppressions.yml", yaml_text)
    removed = remove_suppression(path, "CVE-2026-0001")
    assert removed.cve_id == "CVE-2026-0001"
    remaining = load_suppressions(path)
    assert len(remaining) == 1
    assert remaining[0].cve_id == "CVE-2026-0002"
    assert path.exists()


def test_remove_last_entry_keeps_empty_file(tmp_path: Path) -> None:
    path = _write(tmp_path / "suppressions.yml", _VALID_ENTRY_YAML)
    remove_suppression(path, "CVE-2026-1234")
    assert path.exists()
    assert load_suppressions(path) == ()
    # File contains the explicit empty list, not just absent.
    text = path.read_text()
    assert "suppressions" in text


def test_remove_missing_file_raises(tmp_path: Path) -> None:
    path = tmp_path / "suppressions.yml"
    with pytest.raises(SuppressionsError):
        remove_suppression(path, "CVE-2026-0001")


def test_remove_unknown_cve_id_raises(tmp_path: Path) -> None:
    path = _write(tmp_path / "suppressions.yml", _VALID_ENTRY_YAML)
    with pytest.raises(SuppressionsError) as ei:
        remove_suppression(path, "CVE-2026-9999")
    assert "CVE-2026-9999" in str(ei.value)


# ---------- removal history (audit D-2) ----------


def test_history_path_is_sibling(tmp_path: Path) -> None:
    sup = tmp_path / "security" / "suppressions.yml"
    history = history_path_for(sup)
    assert history == tmp_path / "security" / "suppressions.history.yml"


def test_record_removal_creates_history_file(tmp_path: Path) -> None:
    sup_path = tmp_path / "security" / "suppressions.yml"
    sup_path.parent.mkdir(parents=True, exist_ok=True)
    prior = _make(
        cve_id="CVE-2026-1234", until=date(2026, 8, 1),
        added=date(2026, 5, 6), reason="r", reviewed_by="jon",
    )
    record_removal(sup_path, prior=prior, removed_at=date(2026, 5, 10))
    history = history_path_for(sup_path)
    assert history.exists()
    text = history.read_text()
    assert "CVE-2026-1234" in text
    assert "2026-05-10" in text


def test_find_recent_removal_within_window(tmp_path: Path) -> None:
    sup_path = tmp_path / "security" / "suppressions.yml"
    sup_path.parent.mkdir(parents=True, exist_ok=True)
    prior = _make(
        cve_id="CVE-2026-1234", until=date(2026, 8, 1),
        added=date(2026, 5, 1), reason="reviewed",
    )
    record_removal(sup_path, prior=prior, removed_at=date(2026, 5, 5))
    found = find_recent_removal(
        sup_path, "CVE-2026-1234",
        today=date(2026, 5, 10), max_age_days=7,
    )
    assert found is not None
    assert found.cve_id == "CVE-2026-1234"
    assert found.previous_until == date(2026, 8, 1)
    assert found.previous_added == date(2026, 5, 1)
    assert found.removed_at == date(2026, 5, 5)
    assert found.previous_reason == "reviewed"


def test_find_recent_removal_outside_window(tmp_path: Path) -> None:
    sup_path = tmp_path / "security" / "suppressions.yml"
    sup_path.parent.mkdir(parents=True, exist_ok=True)
    prior = _make(cve_id="CVE-2026-1234")
    record_removal(sup_path, prior=prior, removed_at=date(2026, 1, 1))
    found = find_recent_removal(
        sup_path, "CVE-2026-1234",
        today=date(2026, 5, 10), max_age_days=7,
    )
    # 130 days > 7-day window — treated as not recent.
    assert found is None


def test_find_recent_removal_no_history(tmp_path: Path) -> None:
    sup_path = tmp_path / "security" / "suppressions.yml"
    found = find_recent_removal(
        sup_path, "CVE-2026-1234", today=date(2026, 5, 10),
    )
    assert found is None


def test_find_recent_removal_unknown_cve(tmp_path: Path) -> None:
    sup_path = tmp_path / "security" / "suppressions.yml"
    sup_path.parent.mkdir(parents=True, exist_ok=True)
    prior = _make(cve_id="CVE-2026-1234")
    record_removal(sup_path, prior=prior, removed_at=date(2026, 5, 5))
    assert find_recent_removal(
        sup_path, "CVE-2026-9999", today=date(2026, 5, 10),
    ) is None


def test_record_removal_appends_multiple(tmp_path: Path) -> None:
    sup_path = tmp_path / "security" / "suppressions.yml"
    sup_path.parent.mkdir(parents=True, exist_ok=True)
    prior_a = _make(cve_id="CVE-2026-1111", added=date(2026, 5, 1))
    prior_b = _make(cve_id="CVE-2026-2222", added=date(2026, 5, 2))
    record_removal(sup_path, prior=prior_a, removed_at=date(2026, 5, 5))
    record_removal(sup_path, prior=prior_b, removed_at=date(2026, 5, 6))
    text = history_path_for(sup_path).read_text()
    assert "CVE-2026-1111" in text
    assert "CVE-2026-2222" in text


def test_find_recent_removal_picks_most_recent(tmp_path: Path) -> None:
    """When the same CVE is suppressed, removed, suppressed, removed again,
    the most recent removal is what we surface."""
    sup_path = tmp_path / "security" / "suppressions.yml"
    sup_path.parent.mkdir(parents=True, exist_ok=True)
    prior_old = _make(cve_id="CVE-2026-1234", added=date(2026, 1, 1))
    prior_new = _make(cve_id="CVE-2026-1234", added=date(2026, 5, 1))
    record_removal(sup_path, prior=prior_old, removed_at=date(2026, 1, 5))
    record_removal(sup_path, prior=prior_new, removed_at=date(2026, 5, 8))
    found = find_recent_removal(
        sup_path, "CVE-2026-1234", today=date(2026, 5, 10),
    )
    assert found is not None
    assert found.removed_at == date(2026, 5, 8)
    assert found.previous_added == date(2026, 5, 1)


def test_record_removal_uses_atomic_write(tmp_path: Path) -> None:
    sup_path = tmp_path / "security" / "suppressions.yml"
    sup_path.parent.mkdir(parents=True, exist_ok=True)
    prior = _make(cve_id="CVE-2026-1234")
    record_removal(sup_path, prior=prior, removed_at=date(2026, 5, 5))
    # No leftover .tmp scratch files.
    leftovers = [
        p for p in sup_path.parent.iterdir() if p.suffix == ".tmp"
    ]
    assert leftovers == []
