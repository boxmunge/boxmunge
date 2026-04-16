"""Tests for webhook delivery."""
import json
import pytest
from unittest.mock import patch, MagicMock
from boxmunge.webhooks import fire_webhook, build_payload

class TestBuildPayload:
    def test_includes_required_fields(self):
        payload = build_payload("deploy", "myapp", "box01.example.com",
                                details={"ref": "abc123"})
        assert payload["event"] == "deploy"
        assert payload["project"] == "myapp"
        assert payload["hostname"] == "box01.example.com"
        assert "timestamp" in payload
        assert payload["details"]["ref"] == "abc123"

    def test_empty_details(self):
        payload = build_payload("unstage", "myapp", "box01.example.com")
        assert payload["details"] == {}

class TestFireWebhook:
    @patch("boxmunge.webhooks.urllib.request.urlopen")
    def test_sends_post_request(self, mock_urlopen):
        mock_urlopen.return_value.__enter__ = MagicMock()
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
        config = {
            "webhooks": [{"url": "https://hooks.example.com/test", "events": ["deploy"]}],
            "hostname": "box01.example.com",
        }
        fire_webhook("deploy", "myapp", config)
        mock_urlopen.assert_called_once()
        request = mock_urlopen.call_args[0][0]
        assert request.full_url == "https://hooks.example.com/test"
        body = json.loads(request.data)
        assert body["event"] == "deploy"

    @patch("boxmunge.webhooks.urllib.request.urlopen")
    def test_skips_non_matching_events(self, mock_urlopen):
        config = {
            "webhooks": [{"url": "https://hooks.example.com/test", "events": ["deploy"]}],
            "hostname": "box01.example.com",
        }
        fire_webhook("unstage", "myapp", config)
        mock_urlopen.assert_not_called()

    @patch("boxmunge.webhooks.urllib.request.urlopen")
    def test_fires_to_multiple_matching_hooks(self, mock_urlopen):
        mock_urlopen.return_value.__enter__ = MagicMock()
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
        config = {
            "webhooks": [
                {"url": "https://hooks.example.com/a", "events": ["deploy"]},
                {"url": "https://hooks.example.com/b", "events": ["deploy", "promote"]},
            ],
            "hostname": "box01.example.com",
        }
        fire_webhook("deploy", "myapp", config)
        assert mock_urlopen.call_count == 2

    @patch("boxmunge.webhooks.urllib.request.urlopen")
    def test_failure_does_not_raise(self, mock_urlopen):
        mock_urlopen.side_effect = Exception("Network error")
        config = {
            "webhooks": [{"url": "https://hooks.example.com/test", "events": ["deploy"]}],
            "hostname": "box01.example.com",
        }
        fire_webhook("deploy", "myapp", config)  # should not raise

    def test_no_webhooks_configured(self):
        fire_webhook("deploy", "myapp", {"hostname": "box01.example.com"})

    def test_empty_webhooks_list(self):
        fire_webhook("deploy", "myapp", {"webhooks": [], "hostname": "box01.example.com"})
