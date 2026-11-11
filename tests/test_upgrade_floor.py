# SPDX-License-Identifier: Apache-2.0
"""The upgrade floor: a release refuses, in the shim's pre-flight, to be
installed over a release older than 0.11.0, and names the bridge release."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

from boxmunge.commands.upgrade_cmd import run_upgrade
from boxmunge.paths import BoxPaths
from boxmunge.upgrade_floor import (
    BRIDGE_COMMAND, BRIDGE_RELEASE, BelowUpgradeFloor, UPGRADE_FLOOR, require_upgrade_floor,
)

NEW = "0.11.7"
REPO = Path(__file__).resolve().parents[1]
INSTALL_FLOOR = REPO / "bootstrap" / "upgrade-floor.sh"


def _box(tmp_path: Path, recorded: str | None) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects", "state/deploy", "caddy/sites"]:
        (paths.root / d).mkdir(parents=True)
    paths.config_file.write_text("hostname: test\nadmin_email: t@t\n")
    if recorded is not None:
        paths.version_file.write_text(recorded + "\n")
    return paths


def _snapshot(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_the_floor_and_the_bridge_release() -> None:
    assert UPGRADE_FLOOR == "0.11.0"
    assert BRIDGE_COMMAND == "sudo /opt/boxmunge/bin/boxmunge-upgrade target 0.11.6"


@pytest.mark.parametrize("recorded", [
    "0.11.0", "0.11.0+abc1234", "0.11.1", "0.11.6+abc1234", "0.11.7", "0.12.0", "1.0.0"])
def test_a_box_at_or_above_the_floor_passes(tmp_path: Path, recorded: str) -> None:
    require_upgrade_floor(_box(tmp_path, recorded), NEW)


@pytest.mark.parametrize("recorded", [
    "0.10.1", "0.10.1+abc1234", "0.10.0", "0.9.16", "0.9.1", "0.7.0", "0.6.3", "0.2.0+abc1234"])
def test_a_box_below_the_floor_is_refused_with_the_bridge_command(
        tmp_path: Path, recorded: str) -> None:
    with pytest.raises(BelowUpgradeFloor) as refusal:
        require_upgrade_floor(_box(tmp_path, recorded), f"{NEW}+abc1234")
    message = str(refusal.value)
    installed = recorded.split("+")[0]
    assert f"boxmunge {NEW} cannot be installed over {installed}" in message
    assert "0.11.0 or later" in message
    assert BRIDGE_COMMAND in message
    # The shim blocklists the refused release, never the bridge release.
    assert f"sudo /opt/boxmunge/bin/boxmunge-upgrade clear-blocklist {NEW}" in message
    assert "+abc1234" not in message


def test_a_missing_version_record_is_refused_not_guessed(tmp_path: Path) -> None:
    paths = _box(tmp_path, None)
    with pytest.raises(BelowUpgradeFloor) as refusal:
        require_upgrade_floor(paths, NEW)
    message = str(refusal.value)
    assert str(paths.version_file) in message
    assert "boxmunge-server --version" in message


def test_a_missing_record_says_which_part_of_the_version_output_to_write(tmp_path: Path) -> None:
    """`--version` prints `boxmunge 0.11.6+abc1234`; written whole, that is refused again."""
    paths = _box(tmp_path, None)
    with pytest.raises(BelowUpgradeFloor) as refusal:
        require_upgrade_floor(paths, NEW)
    assert "as X.Y.Z alone" in str(refusal.value)
    assert "(for `boxmunge 0.11.6+abc1234`, write 0.11.6)" in str(refusal.value)
    paths.version_file.write_text("boxmunge 0.11.6+abc1234\n")
    with pytest.raises(BelowUpgradeFloor, match="does not record"):
        require_upgrade_floor(paths, NEW)
    paths.version_file.write_text("0.11.6\n")
    require_upgrade_floor(paths, NEW)


# What config/version holds, byte for byte, and the verdict of both checks:
# "pass", "below" the floor, or "unreadable". One line (the newline optional),
# a version as the shim's SEMVER_RE reads it, an optional +build; compared on
# X.Y.Z alone.
RECORDS = [
    (b"0.11.0\n", "pass"), (b"0.11.0", "pass"), (b"0.11.6+abc1234\n", "pass"),
    (b"0.12.0\n", "pass"), (b"1.0.0\n", "pass"), (b"0.100.0\n", "pass"), (b"0.11.10\n", "pass"),
    (b"0.12.0-rc.1\n", "pass"), (b"0.11.0-rc.1\n", "pass"), (b"0.11.0-rc.1+abc1234", "pass"),
    (b"00.011.00\n", "pass"), (b"0.011.0\n", "pass"),
    (b"99999999999999999999999999.0.0\n", "pass"), (b"0.99999999999999999999999999.0\n", "pass"),
    (b"0.10.99\n", "below"), (b"0.10.1+abc\n", "below"), (b"0.9.16\n", "below"),
    (b"0.10.1-rc.1+abc\n", "below"), (b"0.010.9\n", "below"), (b"0.9.2+0.11.0\n", "below"),
    (b"0.0.99999999999999999999999999\n", "below"),
    (b"", "unreadable"), (b"\n", "unreadable"), (b"unknown\n", "unreadable"),
    (b"v0.11.0\n", "unreadable"), (b"0.11\n", "unreadable"), (b"0.11.0.1\n", "unreadable"),
    (b"0.11.x\n", "unreadable"), (b"boxmunge 0.11.6+abc1234\n", "unreadable"),
    (b"0.11.0\njunk\n", "unreadable"), (b"0.11.0\n\n", "unreadable"), (b"\n0.11.0\n", "unreadable"),
    (b" 0.11.0\n", "unreadable"), (b"0.11.0 \n", "unreadable"), (b"0.11.0\r\n", "unreadable"),
    (b"0.11.0\t\n", "unreadable"), (b"0.11.0+\n", "unreadable"), (b"+0.11.0\n", "unreadable"),
    (b"0.11.0-\n", "unreadable"), (b"0.11.0-rc..1\n", "unreadable"), (b"0.11.0+a+b\n", "unreadable"),
    (b"0.11.0\x00\n", "unreadable"), (b"0.11.0\n\x00", "unreadable"), (b"\x000.11.0\n", "unreadable"),
    (b"0.11.\xc3\xa9\n", "unreadable"), (b"0.\xd9\xa1\xd9\xa1.0\n", "unreadable"), (b"0.11.0\xff\n", "unreadable"),
]
SAID = {"below": "cannot be installed over", "unreadable": "does not record the release this box runs"}


@pytest.mark.parametrize(("record", "verdict"), RECORDS, ids=[repr(r)[2:-1] for r, _ in RECORDS])
def test_the_package_and_install_sh_read_the_version_record_alike(
        tmp_path: Path, record: bytes, verdict: str) -> None:
    paths = _box(tmp_path, None)
    paths.version_file.write_bytes(record)

    try:
        require_upgrade_floor(paths, NEW)
        package = "pass"
    except BelowUpgradeFloor as refusal:
        package = next(name for name, text in SAID.items() if text in str(refusal))
    result = subprocess.run(["bash", str(INSTALL_FLOOR)], capture_output=True, text=True,
                            check=False, env={**os.environ, "BOXMUNGE_ROOT": str(paths.root)})
    if result.returncode == 0:
        install_sh = "pass"
    else:
        assert result.returncode == 1, result.stderr
        install_sh = next(name for name, text in SAID.items() if text in result.stderr)

    assert (package, install_sh) == (verdict, verdict)


class TestDryRun:
    """`upgrade --dry-run` is the pre-flight every shim since 0.5.8 runs
    before it stashes, replaces itself or runs install.sh."""

    def test_refuses_below_the_floor_and_writes_nothing(self, tmp_path: Path, capsys) -> None:
        paths = _box(tmp_path, "0.10.1+abc1234")
        before = _snapshot(paths.root)

        assert run_upgrade(paths, dry_run=True) == 1

        err = capsys.readouterr().err
        assert "cannot be installed over 0.10.1" in err
        assert BRIDGE_COMMAND in err
        assert _snapshot(paths.root) == before

    def test_the_refusal_comes_before_any_project_is_read(self, tmp_path: Path, capsys) -> None:
        """A below-floor box's projects may not even parse in this release:
        the operator must see the floor, not a manifest error."""
        paths = _box(tmp_path, "0.9.1")
        broken = paths.project_dir("old")
        broken.mkdir(parents=True)
        (broken / "manifest.yml").write_text("- not\n- a mapping\n")

        assert run_upgrade(paths, dry_run=True) == 1

        err = capsys.readouterr().err
        assert BRIDGE_COMMAND in err
        assert "manifest" not in err

    def test_passes_at_the_floor(self, tmp_path: Path, capsys) -> None:
        paths = _box(tmp_path, "0.11.0+abc1234")
        assert run_upgrade(paths, dry_run=True) == 0
        assert "Nothing was written" in capsys.readouterr().out


class TestPackageVersionAttribute:
    """Shims of 0.5.8 to 0.9.1 pre-flight a release with
    `print(boxmunge.__version__)`. Those boxes are below the floor, and that
    traceback is the only place this release can speak through such a shim."""

    def test_reading_it_fails_and_names_the_bridge_command(self) -> None:
        import boxmunge
        with pytest.raises(AttributeError) as refusal:
            boxmunge.__version__  # noqa: B018
        assert BRIDGE_COMMAND in str(refusal.value)
        assert "0.11.0 or later" in str(refusal.value)

    def test_other_names_still_raise(self) -> None:
        import boxmunge
        with pytest.raises(AttributeError, match="no_such_name"):
            boxmunge.no_such_name  # noqa: B018

    def test_hasattr_is_false(self) -> None:
        import boxmunge
        assert not hasattr(boxmunge, "__version__")


class TestInstallSh:
    """bootstrap/upgrade-floor.sh: the same floor for install.sh run by hand
    on an existing box, where no shim's pre-flight has run."""

    def _run(self, root: Path) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(INSTALL_FLOOR)], capture_output=True, text=True,
                              check=False, env={**os.environ, "BOXMUNGE_ROOT": str(root)})

    def _recorded(self, tmp_path: Path, recorded: str) -> Path:
        (tmp_path / "config").mkdir()
        (tmp_path / "config" / "version").write_text(recorded + "\n")
        return tmp_path

    def test_it_states_the_floor_and_bridge_the_package_does(self) -> None:
        script = INSTALL_FLOOR.read_text()
        assert re.findall(r'^UPGRADE_FLOOR="(.*)"$', script, re.M) == [UPGRADE_FLOOR]
        assert re.findall(r'^BRIDGE_RELEASE="(.*)"$', script, re.M) == [BRIDGE_RELEASE]

    @pytest.mark.parametrize("recorded", ["0.11.0", "0.11.6+abc1234", "0.11.10", "0.12.0", "1.0.0"])
    def test_a_box_at_or_above_the_floor_passes(self, tmp_path: Path, recorded: str) -> None:
        result = self._run(self._recorded(tmp_path, recorded))
        assert result.returncode == 0, result.stderr
        assert result.stderr == ""

    @pytest.mark.parametrize("recorded", ["0.10.1+abc1234", "0.10.0", "0.9.16", "0.2.0"])
    def test_a_box_below_the_floor_is_refused_with_the_bridge_command(
            self, tmp_path: Path, recorded: str) -> None:
        result = self._run(self._recorded(tmp_path, recorded))
        assert result.returncode == 1
        assert f"cannot be installed over boxmunge {recorded.split('+')[0]}" in result.stderr
        assert f"sudo {tmp_path}/bin/boxmunge-upgrade target {BRIDGE_RELEASE}" in result.stderr
        assert "+abc1234" not in result.stderr

    def test_an_unreadable_record_says_which_part_of_the_version_output_to_write(
            self, tmp_path: Path) -> None:
        result = self._run(self._recorded(tmp_path, "boxmunge 0.11.6+abc1234"))
        assert result.returncode == 1
        assert f"{tmp_path}/config/version does not record" in result.stderr
        assert "(it holds 'boxmunge 0.11.6+abc1234?')" in result.stderr
        assert f"{tmp_path}/env-active/bin/boxmunge-server --version" in result.stderr
        assert "(for `boxmunge 0.11.6+abc1234`, write 0.11.6)" in result.stderr
        assert "Nothing was changed" in result.stderr

    def test_an_interrupted_first_install_is_let_through(self, tmp_path: Path) -> None:
        """No release ever finished installing there: a re-run completes it."""
        (tmp_path / "config").mkdir()
        (tmp_path / "config" / "boxmunge.yml").write_text("hostname: test\n")
        result = self._run(tmp_path)
        assert result.returncode == 0 and result.stderr == ""

    def test_install_sh_checks_before_it_changes_anything(self) -> None:
        install = (REPO / "install.sh").read_text()
        check = install.index('bash "${SCRIPT_DIR}/bootstrap/upgrade-floor.sh"\n')
        assert BRIDGE_COMMAND.split()[1] == "/opt/boxmunge/bin/boxmunge-upgrade"
        assert 'BOXMUNGE_ROOT="/opt/boxmunge"\n' in install[:check]
        for first_change in ("\nremove_dead_crowdsec_repo\n", "\nensure_install_prereqs\n",
                             "bootstrap/init-host.sh"):
            assert check < install.index(first_change)
