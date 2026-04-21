import json
from unittest.mock import patch, MagicMock
from boxmunge.report_failure import report_failure

class TestReportFailure:
    @patch("boxmunge.report_failure.urllib.request.urlopen")
    def test_sends_correct_payload(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 204
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        report_failure("0.2.1", "0.2.0", "preflight")

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        body = json.loads(request.data)
        assert body["version"] == "0.2.1"
        assert body["installed_from"] == "0.2.0"
        assert body["stage"] == "preflight"
        assert "timestamp" in body

    @patch("boxmunge.report_failure.urllib.request.urlopen")
    def test_returns_true_on_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 204
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        assert report_failure("0.2.1", "0.2.0", "apply") is True

    @patch("boxmunge.report_failure.urllib.request.urlopen",
           side_effect=Exception("network down"))
    def test_returns_false_on_failure(self, mock_urlopen):
        assert report_failure("0.2.1", "0.2.0", "apply") is False

    @patch("boxmunge.report_failure.urllib.request.urlopen",
           side_effect=Exception("timeout"))
    def test_does_not_raise_on_failure(self, mock_urlopen):
        result = report_failure("0.2.1", "0.2.0", "health_probation")
        assert result is False
