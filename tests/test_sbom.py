# SPDX-License-Identifier: Apache-2.0
"""The release SBOM (scripts/generate-sbom.sh, scripts/assemble-sbom.py)
lists what a box installs: the package, every hash-pinned Python dependency
the upgrade shim installs into a slot, and the platform components beside
it. Up to v0.11.5 a bad cyclonedx-py flag was hidden by `2>/dev/null ||
true`, and the release shipped a hand-written SBOM with four components."""
from __future__ import annotations

import importlib.util
import json
import re
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
GENERATE = REPO / "scripts" / "generate-sbom.sh"


def _load_module():
    spec = importlib.util.spec_from_file_location("assemble_sbom",
                                                  REPO / "scripts" / "assemble-sbom.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


sbom = _load_module()
BOX_REQUIREMENTS = [REPO / r for r in ("requirements-build.txt", "requirements-tui.txt",
                                       "requirements-mcp.txt")]
VERSION = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["version"]


def _python_bom(drop: str = "", root: str = "boxmunge-server", **versions: str) -> dict:
    """A CycloneDX BOM shaped as cyclonedx-py writes one, for the box's pins."""
    pins = sbom.read_pins(BOX_REQUIREMENTS)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "application", "bom-ref": "root",
                                   "name": root, "version": VERSION}},
        "components": [{"type": "library", "bom-ref": f"{name}=={version}", "name": name,
                        "version": versions.get(name, version)}
                       for name, version in pins.items() if name != drop],
    }


def _names(bom: dict) -> dict[str, str]:
    return {c["name"]: c["version"] for c in bom["components"]}


class TestAssemble:
    def test_the_sbom_lists_the_package_its_dependencies_and_the_platform(self):
        bom = sbom.assemble(_python_bom(), BOX_REQUIREMENTS, REPO)
        assert bom["metadata"]["component"]["name"] == "boxmunge-server"
        assert bom["metadata"]["component"]["version"] == VERSION
        names = _names(bom)
        for package in ("pydantic", "mcp", "textual", "pyyaml", "setuptools"):
            assert package in names, package
        dockerfile = (REPO / "system" / "Dockerfile").read_text()
        assert names["age"] == re.search(r"^ARG AGE_VERSION=(\S+)", dockerfile, re.M)[1]
        assert names["rclone"] == re.search(r"^ARG RCLONE_VERSION=(\S+)", dockerfile, re.M)[1]
        assert names["caddy"] == "2-alpine" and names["postgres"] == "16-alpine"

    def test_the_sbom_is_valid_cyclonedx(self):
        pytest.importorskip("cyclonedx", reason="requirements-dev.txt installs cyclonedx-bom")
        sbom.validate(sbom.assemble(_python_bom(), BOX_REQUIREMENTS, REPO))

    def test_an_invalid_sbom_is_refused(self):
        pytest.importorskip("cyclonedx", reason="requirements-dev.txt installs cyclonedx-bom")
        bom = sbom.assemble(_python_bom(), BOX_REQUIREMENTS, REPO)
        bom["components"][0]["bogus"] = 1
        with pytest.raises(sbom.SbomError, match="bogus"):
            sbom.validate(bom)

    def test_a_missing_pin_is_refused(self):
        with pytest.raises(sbom.SbomError, match="mcp"):
            sbom.assemble(_python_bom(drop="mcp"), BOX_REQUIREMENTS, REPO)

    def test_a_pin_at_another_version_is_refused(self):
        with pytest.raises(sbom.SbomError, match="pydantic"):
            sbom.assemble(_python_bom(pydantic="0.0.1"), BOX_REQUIREMENTS, REPO)

    def test_a_bom_of_another_package_is_refused(self):
        with pytest.raises(sbom.SbomError, match="boxmunge-server"):
            sbom.assemble(_python_bom(root="something-else"), BOX_REQUIREMENTS, REPO)

    def test_names_compare_as_pip_normalises_them(self):
        bom = _python_bom()
        for component in bom["components"]:
            if component["name"] == "typing-extensions":
                component["name"] = "typing_extensions"
        sbom.assemble(bom, BOX_REQUIREMENTS, REPO)


class TestGenerateScript:
    def test_failures_are_not_hidden(self):
        script = GENERATE.read_text()
        assert "|| true" not in script and "2>/dev/null" not in script
        assert "set -euo pipefail" in script

    def test_it_installs_what_the_upgrade_shim_installs(self):
        """The same requirements files as a slot gets (release.sh)."""
        shim = (REPO / "scripts" / "boxmunge-upgrade.d" / "release.sh").read_text()
        pinned = re.search(r"^PINNED_REQUIREMENTS=\(([^)]*)\)", shim, re.M)[1].split()
        listed = re.search(r"^BOX_REQUIREMENTS=\(([^)]*)\)", GENERATE.read_text(), re.M)[1]
        assert listed.split() == pinned

    def test_ci_builds_and_validates_the_real_sbom(self):
        workflow = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text())
        runs = [s.get("run") or "" for s in workflow["jobs"]["unit"]["steps"]]
        assert any("bash scripts/generate-sbom.sh" in run for run in runs)
