"""Tests for boxmunge.pushover — Pushover notification sending."""

import pytest
from unittest.mock import patch, MagicMock

from boxmunge.pushover import format_alert, format_recovery, send_notification


class TestFormatAlert:
    def test_formats_project_alert(self) -> None:
        title, body = format_alert("myapp", "warning", "Backend returned 502")
        assert "myapp" in title
        assert "502" in body

    def test_critical_mentioned(self) -> None:
        title, body = format_alert("myapp", "critical", "Security breach")
        assert "CRITICAL" in title.upper() or "critical" in title.lower()


class TestFormatRecovery:
    def test_formats_recovery(self) -> None:
        title, body = format_recovery("myapp")
        assert "myapp" in title
        assert "recover" in body.lower()


class TestSendNotification:
    @patch("boxmunge.pushover._post_pushover")
    def test_sends_with_credentials(self, mock_post: MagicMock) -> None:
        mock_post.return_value = True
        result = send_notification(
            user_key="ukey",
            app_token="atoken",
            title="Test",
            message="Hello",
        )
        assert result is True
        mock_post.assert_called_once()
        call_data = mock_post.call_args[0][0]
        assert call_data["user"] == "ukey"
        assert call_data["token"] == "atoken"
        assert call_data["title"] == "Test"
        assert call_data["message"] == "Hello"

    @patch("boxmunge.pushover._post_pushover")
    def test_returns_false_on_failure(self, mock_post: MagicMock) -> None:
        mock_post.return_value = False
        result = send_notification("u", "a", "t", "m")
        assert result is False

    def test_missing_credentials_returns_false(self) -> None:
        result = send_notification("", "", "Test", "Hello")
        assert result is False
