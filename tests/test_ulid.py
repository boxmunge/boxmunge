"""Tests for ULID generation."""
import re
from boxmunge.ulid import generate_ulid

ULID_PATTERN = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")


class TestGenerateUlid:
    def test_returns_26_char_string(self) -> None:
        ulid = generate_ulid()
        assert len(ulid) == 26

    def test_valid_crockford_base32(self) -> None:
        ulid = generate_ulid()
        assert ULID_PATTERN.match(ulid), f"Invalid ULID: {ulid}"

    def test_unique_values(self) -> None:
        ulids = {generate_ulid() for _ in range(100)}
        assert len(ulids) == 100

    def test_monotonically_sortable(self) -> None:
        ulids = [generate_ulid() for _ in range(10)]
        assert ulids == sorted(ulids)
