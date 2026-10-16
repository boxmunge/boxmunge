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


def _pins(path: Path) -> dict[str, tuple[str, frozenset[str]]]:
    """Each package's pinned version and its full set of allowed hashes."""
    blocks = re.split(r"^(?=[A-Za-z])", path.read_text(), flags=re.M)
    pins = {}
    for block in blocks:
        m = re.match(r"([A-Za-z][\w.\-]*)(?:\[[^\]]*\])?==(\S+)", block)
        if m:
            hashes = frozenset(re.findall(r"--hash=sha256:([0-9a-f]{64})", block))
            pins[m.group(1).lower()] = (m.group(2), hashes)
    return pins


def test_onbox_requirements_agree_where_they_overlap() -> None:
    """They are installed in one pip run; a package pinned to two versions, or
    to one version with different hash sets, makes pip refuse or narrows what
    it accepts. `make lock` keeps them in step."""
    seen: dict[str, tuple[tuple[str, frozenset[str]], str]] = {}
    for name in ONBOX_REQUIREMENTS:
        for pkg, pin in _pins(REPO / name).items():
            assert pin[1], f"{pkg} in {name} has no hashes"
            first = seen.setdefault(pkg, (pin, name))
            assert first[0][0] == pin[0], f"{pkg}: {first[0][0]} in {first[1]}, {pin[0]} in {name}"
            assert first[0][1] == pin[1], f"{pkg} {pin[0]}: hash sets differ between {first[1]} and {name}"
    assert len(seen) > 30, "no packages parsed"
