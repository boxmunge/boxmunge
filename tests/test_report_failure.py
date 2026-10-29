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


class TestEndpointOverride:
    def test_conftest_points_at_closed_local_port(self):
        from boxmunge.version_check_url import version_check_base
        assert version_check_base() == "http://127.0.0.1:9"

    def test_env_overrides_the_default(self, monkeypatch):
        from boxmunge.version_check_url import version_check_base
        monkeypatch.delenv("BOXMUNGE_VERSION_CHECK_URL")
        assert version_check_base() == "https://boxmunge.dev"
        monkeypatch.setenv("BOXMUNGE_VERSION_CHECK_URL", "http://127.0.0.1:1234/")
        assert version_check_base() == "http://127.0.0.1:1234"

    @patch("boxmunge.report_failure.urllib.request.urlopen")
    def test_report_goes_to_the_override(self, mock_urlopen):
        mock_urlopen.side_effect = OSError("refused")
        report_failure("0.2.1", "0.2.0", "apply")
        assert mock_urlopen.call_args[0][0].full_url == "http://127.0.0.1:9/v1/report-failure"


class TestDetailAndDiagnostics:
    @patch("boxmunge.report_failure.urllib.request.urlopen")
    def test_detail_is_sent_printable_and_capped(self, mock_urlopen, capsys):
        mock_urlopen.side_effect = OSError("refused")
        report_failure("0.2.1", "0.2.0", "preflight", "bad\x00é " + "x" * 500)
        detail = json.loads(mock_urlopen.call_args[0][0].data)["detail"]
        assert len(detail) == 200 and detail.startswith("bad?? x")

    @patch("boxmunge.report_failure.urllib.request.urlopen")
    def test_no_detail_field_when_empty(self, mock_urlopen):
        mock_urlopen.side_effect = OSError("refused")
        report_failure("0.2.1", "0.2.0", "preflight")
        assert "detail" not in json.loads(mock_urlopen.call_args[0][0].data)

    @patch("boxmunge.report_failure.urllib.request.urlopen",
           side_effect=OSError("connection refused"))
    def test_failure_to_send_says_why_on_stderr(self, mock_urlopen, capsys):
        assert report_failure("0.2.1", "0.2.0", "apply") is False
        err = capsys.readouterr().err
        assert err.count("\n") == 1
        assert "could not send" in err and "connection refused" in err
