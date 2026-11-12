# SPDX-License-Identifier: Apache-2.0
"""Which release upgrade-howto and upgrade-check are about (boxmunge.upgrade_target)."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.paths import BoxPaths
from boxmunge.upgrade_shim import check_command, guide_command, sudo_refusal
from boxmunge.upgrade_target import (
    TargetError, installed_release, is_newer, resolve_target,
)

SHIM = "/opt/boxmunge/bin/boxmunge-upgrade"
DISCOVER = "boxmunge.upgrade_target.discover_update"


def _box(tmp_path: Path, *, version: str = "0.11.8+abc1234", optout: bool = False) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    paths.config.mkdir(parents=True)
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n"
                                 + ("version_check:\n  enabled: false\n" if optout else ""))
    paths.version_file.write_text(version + "\n")
    return paths


def _refused(paths: BoxPaths, explicit: str | None) -> TargetError:
    with pytest.raises(TargetError) as caught:
        resolve_target(paths, explicit)
    return caught.value


def test_explicit_version_never_calls_discovery(tmp_path: Path) -> None:
    with patch(DISCOVER, side_effect=AssertionError("discovery was asked")):
        assert resolve_target(_box(tmp_path), "0.12.0") == "0.12.0"


def test_explicit_version_on_an_opted_out_box_asks_nobody(tmp_path: Path) -> None:
    with patch(DISCOVER, side_effect=AssertionError("discovery was asked")), \
         patch("urllib.request.urlopen", side_effect=AssertionError("network")):
        assert resolve_target(_box(tmp_path, optout=True), "0.12.0") == "0.12.0"


def test_opted_out_without_version_exits_2_naming_the_flag(tmp_path: Path) -> None:
    with patch(DISCOVER, side_effect=AssertionError("discovery was asked")):
        error = _refused(_box(tmp_path, optout=True), None)
    assert error.exit_code == 2
    assert "version_check.enabled: false" in error.message
    assert "--version X.Y.Z" in error.message


def test_unreadable_config_without_version_exits_1_naming_the_flag(tmp_path: Path) -> None:
    paths = _box(tmp_path)
    paths.config_file.write_text("version_check: [\n")
    with patch(DISCOVER, side_effect=AssertionError("discovery was asked")):
        error = _refused(paths, None)
    assert error.exit_code == 1
    assert "boxmunge.yml" in error.message and "--version X.Y.Z" in error.message


def test_latest_from_discovery(tmp_path: Path) -> None:
    with patch(DISCOVER, return_value={"action": "upgrade", "version": "0.12.0"}) as asked:
        assert resolve_target(_box(tmp_path), None) == "0.12.0"
    assert asked.call_args[0][1] == "latest"


def test_a_blocklisted_latest_is_still_the_target(tmp_path: Path) -> None:
    """The shim's check names clear-blocklist; the guide is still worth reading."""
    with patch(DISCOVER, return_value={"action": "blocklisted", "version": "0.12.0"}):
        assert resolve_target(_box(tmp_path), None) == "0.12.0"


def test_up_to_date_gives_the_installed_release(tmp_path: Path) -> None:
    with patch(DISCOVER, return_value={"action": "up_to_date"}):
        assert resolve_target(_box(tmp_path), None) == "0.11.8"


def test_discovery_error_exit_1(tmp_path: Path) -> None:
    with patch(DISCOVER, return_value={"action": "error", "message": "Cannot use boxmunge.dev"}):
        error = _refused(_box(tmp_path), None)
    assert error.exit_code == 1
    assert "Cannot use boxmunge.dev" in error.message
    assert "--version X.Y.Z" in error.message


def test_an_unknown_discovery_answer_fails_noisily(tmp_path: Path) -> None:
    with patch(DISCOVER, return_value={"action": "maybe"}):
        error = _refused(_box(tmp_path), None)
    assert error.exit_code == 1 and "'maybe'" in error.message


def test_a_malformed_discovered_version_fails_noisily(tmp_path: Path) -> None:
    with patch(DISCOVER, return_value={"action": "upgrade", "version": "0.12"}):
        error = _refused(_box(tmp_path), None)
    assert error.exit_code == 1 and "'0.12'" in error.message


@pytest.mark.parametrize("bad", ["0.12", "v0.12.0", "0.12.0-rc.1", "0.12.0+abc", "00.12.0",
                                 "0.12.0 ", "--json", ""])
def test_bad_version_exit_2(tmp_path: Path, bad: str) -> None:
    error = _refused(_box(tmp_path), bad)
    assert error.exit_code == 2
    assert "X.Y.Z" in error.message


def test_a_pre_release_box_must_name_the_release(tmp_path: Path) -> None:
    """Discovery cannot compare a pre-release with releases (it would say up
    to date), so the release must be named."""
    with patch(DISCOVER, side_effect=AssertionError("discovery was asked")):
        error = _refused(_box(tmp_path, version="0.12.0-rc.1+abc"), None)
    assert error.exit_code == 2
    assert "0.12.0-rc.1" in error.message and "--version X.Y.Z" in error.message


class TestInstalledRelease:
    def test_the_build_is_dropped(self, tmp_path: Path) -> None:
        assert installed_release(_box(tmp_path, version="0.11.8+abc1234")) == "0.11.8"

    def test_a_pre_release_is_kept(self, tmp_path: Path) -> None:
        assert installed_release(_box(tmp_path, version="0.12.0-rc.1+abc")) == "0.12.0-rc.1"

    @pytest.mark.parametrize("record", ["", "0.11", "garbage", "0.11.8\n0.11.9", "0.011.8"])
    def test_a_record_that_is_no_release_fails_naming_the_file(
            self, tmp_path: Path, record: str) -> None:
        paths = _box(tmp_path)
        paths.version_file.write_text(record)
        with pytest.raises(TargetError) as caught:
            installed_release(paths)
        assert caught.value.exit_code == 1
        assert str(paths.version_file) in caught.value.message
        assert "boxmunge-server --version" in caught.value.message

    def test_a_missing_record_fails_naming_the_file(self, tmp_path: Path) -> None:
        paths = _box(tmp_path)
        paths.version_file.unlink()
        with pytest.raises(TargetError) as caught:
            installed_release(paths)
        assert str(paths.version_file) in caught.value.message


@pytest.mark.parametrize("target,installed,newer", [
    ("0.12.0", "0.11.8", True), ("0.11.8", "0.11.8", False), ("0.11.7", "0.11.8", False),
    ("0.12.0", "0.12.0-rc.1", True), ("0.11.9", "0.12.0-rc.1", False),
    ("0.12.1", "0.12.0-rc.1", True), ("1.0.0", "0.99.99", True),
])
def test_is_newer_orders_a_pre_release_before_its_release(
        target: str, installed: str, newer: bool) -> None:
    assert is_newer(target, installed) is newer


def test_shim_argv_for_check_and_guide() -> None:
    paths = BoxPaths()
    assert check_command(paths, "0.12.0") == ["sudo", "-n", SHIM, "check", "0.12.0"]
    assert guide_command(paths, "0.12.0") == ["sudo", "-n", SHIM, "guide", "0.12.0"]


@pytest.mark.parametrize("stderr", [
    "sudo: a password is required\n",
    "Sorry, user deploy is not allowed to execute '/opt/boxmunge/bin/boxmunge-upgrade guide "
    "0.12.0' as root on box.\n",
    "deploy is not in the sudoers file.\n",
    "sudo: unable to resolve host box: Name or service not known\nsudo: a password is "
    "required\n",
])
def test_sudo_refusal_names_install_sudoers(stderr: str) -> None:
    assert "boxmunge-upgrade install-sudoers" in sudo_refusal(stderr)


@pytest.mark.parametrize("stderr", [
    "sudo: unable to resolve host box: Name or service not known\nboxmunge-upgrade: Failed "
    "to download upgrade-notes.json of 0.12.0 (curl exit 6); retry later\n",
    "",
    "2026-11-12T00:00:00Z boxmunge-upgrade: FATAL: sudo: a password is required\n",
    "boxmunge-upgrade: FATAL: Release 0.12.0 publishes no upgrade-notes.json\n",
])
def test_sudo_warnings_and_shim_errors_are_not_a_refusal(stderr: str) -> None:
    assert sudo_refusal(stderr) is None
