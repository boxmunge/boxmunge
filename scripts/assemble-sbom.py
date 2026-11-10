#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Assemble the release SBOM for scripts/generate-sbom.sh.

  assemble-sbom.py --python-bom FILE --out FILE REQUIREMENTS...

FILE is the CycloneDX JSON cyclonedx-py wrote for a venv built from the
hash-pinned REQUIREMENTS files the upgrade shim installs into a slot. It is
refused unless its root component is boxmunge-server at pyproject.toml's
version and it lists every pin of REQUIREMENTS at its pinned version. The
platform components boxes run beside the package are added: age and rclone
from system/Dockerfile, and the images of caddy/compose.yml and
canary/compose.yml. The result is validated against the CycloneDX schema
(cyclonedx-python-lib, from requirements-dev.txt) and written to --out.
Exits 1 with an ERROR: line on any failure.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKAGE = "boxmunge-server"
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s\\;]+)")
_ARG = r"^ARG {}_VERSION=(\S+)$"
_IMAGE = re.compile(r"^\s*image:\s*[\"']?([^\s\"'#]+)", re.MULTILINE)
PLATFORM_COMPOSE = ("caddy/compose.yml", "canary/compose.yml")


class SbomError(Exception):
    """The SBOM would not describe what a box installs."""


def canonical(name: str) -> str:
    """A distribution name as pip compares them (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def read_pins(paths: list[Path]) -> dict[str, str]:
    """{canonical name: version} of every `name==version` line in `paths`."""
    pins: dict[str, str] = {}
    for path in paths:
        for line in Path(path).read_text().splitlines():
            match = _PIN.match(line)
            if not match:
                continue
            name, version = canonical(match[1]), match[2]
            if pins.setdefault(name, version) != version:
                raise SbomError(f"{name} is pinned at both {pins[name]} and {version} in "
                                f"{', '.join(str(p) for p in paths)}")
    return pins


def platform_components(repo: Path) -> list[dict]:
    """The binaries in the system image and the images boxes pull."""
    dockerfile = (repo / "system" / "Dockerfile").read_text()
    components = []
    for name, project in (("age", "filosottile/age"), ("rclone", "rclone/rclone")):
        match = re.search(_ARG.format(name.upper()), dockerfile, re.MULTILINE)
        if not match:
            raise SbomError(f"system/Dockerfile has no ARG {name.upper()}_VERSION")
        components.append({"type": "application", "bom-ref": f"platform:{name}",
                           "name": name, "version": match[1],
                           "purl": f"pkg:github/{project}@v{match[1]}"})
    for compose in PLATFORM_COMPOSE:
        images = _IMAGE.findall((repo / compose).read_text())
        if not images:
            raise SbomError(f"{compose} names no image")
        for image in images:
            name, _, tag = image.partition(":")
            if not tag:
                raise SbomError(f"{compose}: image {image} has no tag")
            components.append({"type": "container", "bom-ref": f"platform:{name}:{tag}",
                               "name": name, "version": tag,
                               "purl": f"pkg:docker/{name}@{tag}"})
    return components


def assemble(python_bom: dict, requirements: list[Path], repo: Path = REPO) -> dict:
    """`python_bom` checked against the pins, with the platform components."""
    version = tomllib.loads((repo / "pyproject.toml").read_text())["project"]["version"]
    root = python_bom.get("metadata", {}).get("component", {})
    if (root.get("name"), root.get("version")) != (PACKAGE, version):
        raise SbomError(f"the Python BOM describes {root.get('name')} {root.get('version')}, "
                        f"not {PACKAGE} {version}")
    listed = {canonical(c["name"]): c.get("version") for c in python_bom.get("components", [])}
    wrong = [f"{name}=={pin} (BOM: {listed.get(name, 'missing')})"
             for name, pin in read_pins(requirements).items() if listed.get(name) != pin]
    if wrong:
        raise SbomError("the Python BOM does not list every pin a box installs: "
                        + ", ".join(wrong))
    return {**python_bom,
            "components": [*python_bom.get("components", []), *platform_components(repo)]}


def validate(bom: dict) -> None:
    """Refuse a BOM that is not valid CycloneDX JSON of its spec version."""
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    validator = JsonStrictValidator(SchemaVersion.from_version(bom["specVersion"]))
    error = validator.validate_str(json.dumps(bom))
    if error is not None:
        raise SbomError(f"not valid CycloneDX {bom['specVersion']} JSON: {error}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--python-bom", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("requirements", nargs="+")
    args = parser.parse_args(argv)
    try:
        bom = assemble(json.loads(Path(args.python_bom).read_text()),
                       [Path(r) for r in args.requirements])
        validate(bom)
    except SbomError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    Path(args.out).write_text(json.dumps(bom, indent=2) + "\n")
    print(f"{args.out}: {len(bom['components'])} components, CycloneDX {bom['specVersion']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
