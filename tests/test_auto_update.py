"""Tests for auto-update orchestration — discovery is delegated to upgrade_discovery."""

import json
from unittest.mock import patch

import pytest

from boxmunge.commands.auto_update_cmd import run_auto_update
from boxmunge.paths import BoxPaths

BASE = "hostname: t\nadmin_email: a@b\n"
URL = "https://github.com/boxmunge/boxmunge/releases/tag/v0.3.6"


@pytest.fixture
def box(paths: BoxPaths) -> BoxPaths:
    paths.config_file.write_text(BASE)
    return paths


def _upgrade(cls: str, **extra) -> dict:
    return {"action": "upgrade", "version": "0.3.6", "url": URL, "class": cls,
            "source": "endpoint", **extra}


def _log_entries(paths: BoxPaths) -> list[dict]:
    log_file = paths.root / "logs" / "boxmunge.log"
    return [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]


class TestPolicy:
    @patch("boxmunge.upgrade_discovery.discover_update")
    def test_breakfix_enabled_by_default(self, mock_discover, box) -> None:
        mock_discover.return_value = {"action": "up_to_date", "current_version": "0.3.5",
                                      "source": "endpoint"}
        assert run_auto_update(box) == 0
        assert mock_discover.call_args.kwargs["mode"] == "breakfix"

    @patch("boxmunge.upgrade_discovery.discover_update")
    def test_breakfix_disabled_applies_security_only(self, mock_discover, box) -> None:
        box.config_file.write_text(BASE + "auto_update:\n  breakfix: false\n")
        mock_discover.return_value = {"action": "up_to_date", "current_version": "0.3.5",
                                      "source": "endpoint"}
        assert run_auto_update(box) == 0
        assert mock_discover.call_args.kwargs["mode"] == "security"

    @patch("boxmunge.upgrade_discovery.discover_update")
    def test_invalid_policy_fails_loudly(self, mock_discover, box, capsys) -> None:
        box.config_file.write_text(BASE + "auto_update:\n  breakfix: \"no\"\n")
        assert run_auto_update(box) == 1
        mock_discover.assert_not_called()
        assert "auto_update.breakfix" in capsys.readouterr().err


class TestDispatch:
    """run_auto_update dispatches on the four discover_update action types."""

    @pytest.mark.parametrize("cls", ["security", "breakfix"])
    @patch("os.execvp")
    @patch("boxmunge.upgrade_discovery.discover_update")
    def test_upgrade_dispatches_to_shim_with_class(
        self, mock_discover, mock_exec, box, cls
    ) -> None:
        mock_discover.return_value = _upgrade(cls)
        run_auto_update(box)
        shim = str(box.bin / "boxmunge-upgrade")
        mock_exec.assert_called_once_with(shim, [shim, "run", "0.3.6", URL, cls])

    @patch("os.execvp")
    @patch("boxmunge.upgrade_discovery.discover_update")
    def test_upgrade_logs_the_class(self, mock_discover, mock_exec, box, capsys) -> None:
        mock_discover.return_value = _upgrade("breakfix")
        run_auto_update(box)
        assert "Applying breakfix release 0.3.6" in capsys.readouterr().out
        entry = [e for e in _log_entries(box) if e.get("component") == "auto-update"][-1]
        assert entry["msg"] == "Applying breakfix release 0.3.6"
        assert entry["detail"]["class"] == "breakfix"
        assert entry["detail"]["policy"] == "breakfix"

    @patch("os.execvp")
    @patch("boxmunge.upgrade_discovery.discover_update")
    def test_github_fallback_is_warned(self, mock_discover, mock_exec, box, capsys) -> None:
        mock_discover.return_value = _upgrade("security", source="github",
                                              endpoint_error="no 'breakfix' field")
        run_auto_update(box)
        assert "no 'breakfix' field" in capsys.readouterr().err
        levels = [e["level"] for e in _log_entries(box) if e.get("component") == "auto-update"]
        assert "warn" in levels

    @patch("os.execvp")
    @patch("boxmunge.upgrade_discovery.discover_update")
    def test_blocklisted_skipped_no_exec(self, mock_discover, mock_exec, box) -> None:
        mock_discover.return_value = {"action": "blocklisted", "version": "0.3.6",
                                      "class": "breakfix", "source": "endpoint"}
        assert run_auto_update(box) == 0
        mock_exec.assert_not_called()

    @patch("boxmunge.upgrade_discovery.discover_update")
    def test_error_action_returns_one(self, mock_discover, box) -> None:
        mock_discover.return_value = {"action": "error", "message": "endpoint unreachable"}
        assert run_auto_update(box) == 1

    @patch("boxmunge.upgrade_discovery.discover_update")
    def test_unknown_action_returns_one(self, mock_discover, box) -> None:
        mock_discover.return_value = {"action": "wat"}
        assert run_auto_update(box) == 1


class TestUpgradeLock:
    """C-21: discovery runs under upgrade.lock."""

    def _hold(self, paths: BoxPaths) -> int:
        import fcntl
        import os
        paths.upgrade_state.mkdir(parents=True, exist_ok=True)
        fd = os.open(paths.upgrade_lock, os.O_CREAT | os.O_WRONLY)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    @patch("os.execvp")
    @patch("boxmunge.upgrade_discovery.discover_update")
    def test_skips_discovery_while_an_upgrade_runs(self, mock_discover, mock_exec, box) -> None:
        import os
        fd = self._hold(box)
        try:
            assert run_auto_update(box) == 0
        finally:
            os.close(fd)
        mock_discover.assert_not_called()
        mock_exec.assert_not_called()

    @patch("boxmunge.upgrade_discovery.discover_update")
    def test_discovery_holds_the_lock_and_releases_it_before_exec(self, mock_discover, box) -> None:
        from boxmunge.upgrade_state import UpgradeInProgress, upgrade_lock
        held_during_discovery = []

        def discover(*_a, **_k):
            try:
                with upgrade_lock(box):
                    held_during_discovery.append(False)
            except UpgradeInProgress:
                held_during_discovery.append(True)
            return _upgrade("security")

        mock_discover.side_effect = discover

        def exec_shim(*_a):
            with upgrade_lock(box):  # raises if still held
                pass

        with patch("os.execvp", side_effect=exec_shim):
            run_auto_update(box)
        assert held_during_discovery == [True]

    def test_symlinked_lock_is_refused(self, paths, tmp_path) -> None:
        import pytest
        from boxmunge.upgrade_state import upgrade_lock
        paths.upgrade_state.mkdir(parents=True, exist_ok=True)
        victim = tmp_path / "victim"
        victim.write_text("keep")
        paths.upgrade_lock.symlink_to(victim)
        with pytest.raises(OSError):
            with upgrade_lock(paths):
                pass
        assert victim.read_text() == "keep"
