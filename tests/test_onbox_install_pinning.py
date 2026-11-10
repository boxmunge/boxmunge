# SPDX-License-Identifier: Apache-2.0
"""F-06: on-box installs (install.sh and its bootstrap/venv-deps.sh, the
upgrade shim's venv build) take Python dependencies only from the signed
bundle's hash-pinned requirements."""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _built_shim() -> str:
    """The shim as releases ship it, its libraries inlined (scripts/build-shim.py)."""
    spec = importlib.util.spec_from_file_location("build_shim", REPO / "scripts" / "build-shim.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build(REPO / "scripts" / "boxmunge-upgrade")


ONBOX_SCRIPTS = {
    "install.sh": lambda: (REPO / "install.sh").read_text(),
    "venv-deps.sh": lambda: (REPO / "bootstrap" / "venv-deps.sh").read_text(),
    "boxmunge-upgrade": _built_shim,
}
# The two that install a venv's dependencies: install.sh's helper and the shim.
VENV_BUILDERS = ["venv-deps.sh", "boxmunge-upgrade"]


def _pip_install_commands(text: str) -> list[str]:
    """Each `pip install` command, with backslash continuations joined."""
    joined = re.sub(r"\\\n\s*", " ", text)
    return [
        line.strip() for line in joined.splitlines()
        if re.search(r"/pip\"? install", line) and not line.lstrip().startswith("#")
    ]


def _bundle_top_files() -> set[str]:
    m = re.search(r"^BUNDLE_TOP_FILES\s*:=\s*(.+)$", (REPO / "Makefile").read_text(), re.M)
    assert m, "BUNDLE_TOP_FILES not found in Makefile"
    return set(m.group(1).split())


@pytest.mark.parametrize("script", ONBOX_SCRIPTS)
def test_every_pip_install_is_hash_pinned_or_no_deps(script: str) -> None:
    commands = _pip_install_commands(ONBOX_SCRIPTS[script]())
    assert commands, f"no pip install found in {script}"
    for cmd in commands:
        pinned = "--require-hashes" in cmd
        own_package = "--no-deps" in cmd and "--no-build-isolation" in cmd
        assert pinned or own_package, f"{script}: unpinned install: {cmd}"
        assert "--upgrade pip" not in cmd, f"{script}: unpinned pip self-upgrade: {cmd}"


@pytest.mark.parametrize("script", VENV_BUILDERS)
def test_requirements_used_on_box_ship_in_the_bundle(script: str) -> None:
    used = set(re.findall(r"(requirements[\w-]*\.txt)", ONBOX_SCRIPTS[script]()))
    assert used, f"{script} installs from no requirements file"
    missing = used - _bundle_top_files()
    assert not missing, f"{script} uses {missing}, not in BUNDLE_TOP_FILES"


def test_shim_keeps_install_sh_out_of_the_venvs() -> None:
    """install.sh run by the shim must not install into env-active, which is
    still the previous release (the rollback target) at that point; it
    completes the standby instead (tests/test_venv_deps.py)."""
    shim = (REPO / "scripts" / "boxmunge-upgrade.d" / "system.sh").read_text()
    assert 'bash "$new_install_sh" --upgrade-shim' in shim
    install = (REPO / "install.sh").read_text()
    assert 'if [[ "${FROM_UPGRADE_SHIM}" -eq 0 ]]; then' in install


# Every slot is built from scratch, so a dependency left out of these files is
# lost on each upgrade. MCP is part of every install (docs/on-server/OPERATIONS.md).
ONBOX_REQUIREMENTS = ["requirements-build.txt", "requirements-tui.txt", "requirements-mcp.txt"]


@pytest.mark.parametrize("script", VENV_BUILDERS)
def test_every_onbox_venv_gets_the_mcp_requirements(script: str) -> None:
    used = set(re.findall(r"(requirements[\w-]*\.txt)", ONBOX_SCRIPTS[script]()))
    assert set(ONBOX_REQUIREMENTS) <= used, f"{script} installs only {sorted(used)}"


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
