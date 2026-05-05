"""Tests for auto-update orchestration — discovery is delegated to upgrade_discovery."""

from pathlib import Path
from unittest.mock import patch

from boxmunge.commands.auto_update_cmd import run_auto_update
from boxmunge.paths import BoxPaths


class TestRunAutoUpdate:
    """run_auto_update dispatches on the four discover_update action types."""

    @patch("boxmunge.upgrade_discovery.discover_update")
    def test_up_to_date_returns_zero(self, mock_discover, paths) -> None:
        mock_discover.return_value = {
            "action": "up_to_date", "current_version": "0.3.5",
        }
        assert run_auto_update(paths) == 0

    @patch("os.execvp")
    @patch("boxmunge.upgrade_discovery.discover_update")
    def test_security_update_dispatches_to_shim(
        self, mock_discover, mock_exec
    ) -> None:
        mock_discover.return_value = {
            "action": "upgrade",
            "version": "0.3.6",
            "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.3.6",
            "is_security": True,
        }
        paths = BoxPaths(root=Path("/tmp/test-bm"))
        run_auto_update(paths)
        mock_exec.assert_called_once()
        call_args = mock_exec.call_args[0]
        assert call_args[0] == "/tmp/test-bm/bin/boxmunge-upgrade"
        assert "run" in call_args[1]
        assert "0.3.6" in call_args[1]

    @patch("os.execvp")
    @patch("boxmunge.upgrade_discovery.discover_update")
    def test_blocklisted_skipped_no_exec(
        self, mock_discover, mock_exec, paths
    ) -> None:
        mock_discover.return_value = {
            "action": "blocklisted", "version": "0.3.6",
        }
        result = run_auto_update(paths)
        mock_exec.assert_not_called()
        assert result == 0

    @patch("boxmunge.upgrade_discovery.discover_update")
    def test_error_action_returns_one(self, mock_discover, paths) -> None:
        mock_discover.return_value = {
            "action": "error", "message": "endpoint unreachable",
        }
        assert run_auto_update(paths) == 1

    @patch("boxmunge.upgrade_discovery.discover_update")
    def test_unknown_action_returns_one(self, mock_discover, paths) -> None:
        mock_discover.return_value = {"action": "wat"}
        assert run_auto_update(paths) == 1
