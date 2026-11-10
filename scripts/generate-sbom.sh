#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# scripts/generate-sbom.sh: write the release's SBOM, dist/sbom.json
# (CycloneDX JSON), from the repository root.
#
# The Python part describes what a box installs, not this runner's
# environment: a throwaway venv built as the upgrade shim builds a slot (the
# hash-pinned BOX_REQUIREMENTS, the same list as PINNED_REQUIREMENTS in
# scripts/boxmunge-upgrade.d/release.sh, then the package with no further
# resolution), read by cyclonedx-py. scripts/assemble-sbom.py checks it lists
# every pin, adds the platform components and validates the result. Needs
# requirements-dev.txt (cyclonedx-bom) installed in python3's environment.
# Any failure fails the script.
set -euo pipefail

BOX_REQUIREMENTS=(requirements-build.txt requirements-tui.txt requirements-mcp.txt)

cd "$(dirname "$0")/.."
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "Generating SBOM..."
reqs=()
for req in "${BOX_REQUIREMENTS[@]}"; do reqs+=(-r "$req"); done
python3 -m venv "$work/venv"
pip=("$work/venv/bin/pip" install --quiet --disable-pip-version-check --no-cache-dir)
"${pip[@]}" --require-hashes "${reqs[@]}"
"${pip[@]}" --no-deps --no-build-isolation .

python3 -m cyclonedx_py environment --pyproject pyproject.toml --of JSON \
    --output-reproducible --output-file "$work/sbom-python.json" "$work/venv/bin/python"
mkdir -p dist
python3 scripts/assemble-sbom.py --python-bom "$work/sbom-python.json" --out dist/sbom.json \
    "${BOX_REQUIREMENTS[@]}"
