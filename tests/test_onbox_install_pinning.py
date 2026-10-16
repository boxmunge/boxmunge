# SPDX-License-Identifier: Apache-2.0
"""F-06: on-box installs (install.sh, the upgrade shim's venv build) take
Python dependencies only from the signed bundle's hash-pinned requirements."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ONBOX_SCRIPTS = [REPO / "install.sh", REPO / "scripts" / "boxmunge-upgrade"]


def _pip_install_commands(path: Path) -> list[str]:
    """Each `pip install` command, with backslash continuations joined."""
    joined = re.sub(r"\\\n\s*", " ", path.read_text())
    return [
        line.strip() for line in joined.splitlines()
        if re.search(r"/pip\"? install", line) and not line.lstrip().startswith("#")
    ]


def _bundle_top_files() -> set[str]:
    m = re.search(r"^BUNDLE_TOP_FILES\s*:=\s*(.+)$", (REPO / "Makefile").read_text(), re.M)
    assert m, "BUNDLE_TOP_FILES not found in Makefile"
    return set(m.group(1).split())


@pytest.mark.parametrize("script", ONBOX_SCRIPTS, ids=lambda p: p.name)
def test_every_pip_install_is_hash_pinned_or_no_deps(script: Path) -> None:
    commands = _pip_install_commands(script)
    assert commands, f"no pip install found in {script.name}"
    for cmd in commands:
        pinned = "--require-hashes" in cmd
        own_package = "--no-deps" in cmd and "--no-build-isolation" in cmd
        assert pinned or own_package, f"{script.name}: unpinned install: {cmd}"
        assert "--upgrade pip" not in cmd, f"{script.name}: unpinned pip self-upgrade: {cmd}"


@pytest.mark.parametrize("script", ONBOX_SCRIPTS, ids=lambda p: p.name)
def test_requirements_used_on_box_ship_in_the_bundle(script: Path) -> None:
    used = set(re.findall(r"(requirements[\w-]*\.txt)", script.read_text()))
    assert used, f"{script.name} installs from no requirements file"
    missing = used - _bundle_top_files()
    assert not missing, f"{script.name} uses {missing}, not in BUNDLE_TOP_FILES"


def test_shim_keeps_install_sh_out_of_the_venvs() -> None:
    """install.sh run by the shim must not install into env-active, which is
    still the previous release (the rollback target) at that point."""
    shim = (REPO / "scripts" / "boxmunge-upgrade").read_text()
    assert 'bash "$new_install_sh" --upgrade-shim' in shim
    install = (REPO / "install.sh").read_text()
    assert 'if [[ "${FROM_UPGRADE_SHIM}" -eq 0 ]]; then' in install


# Every slot is built from scratch, so a dependency left out of these files is
# lost on each upgrade. MCP is part of every install (docs/on-server/OPERATIONS.md).
ONBOX_REQUIREMENTS = ["requirements-build.txt", "requirements-tui.txt", "requirements-mcp.txt"]


@pytest.mark.parametrize("script", ONBOX_SCRIPTS, ids=lambda p: p.name)
def test_every_onbox_venv_gets_the_mcp_requirements(script: Path) -> None:
    used = set(re.findall(r"(requirements[\w-]*\.txt)", script.read_text()))
    assert set(ONBOX_REQUIREMENTS) <= used, f"{script.name} installs only {sorted(used)}"


def _pins(path: Path) -> dict[str, str]:
    return {
        m.group(1).lower(): m.group(2)
        for m in re.finditer(r"^([A-Za-z][\w.\-]*)(?:\[[^\]]*\])?==(\S+)", path.read_text(), re.M)
    }


def test_onbox_requirements_agree_where_they_overlap() -> None:
    """They are installed in one pip run; a package pinned to two versions
    would make every install and upgrade fail. `make lock` keeps them in step."""
    seen: dict[str, tuple[str, str]] = {}
    for name in ONBOX_REQUIREMENTS:
        for pkg, version in _pins(REPO / name).items():
            first = seen.setdefault(pkg, (version, name))
            assert first[0] == version, f"{pkg}: {first[0]} in {first[1]}, {version} in {name}"
