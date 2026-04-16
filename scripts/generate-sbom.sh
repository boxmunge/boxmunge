#!/usr/bin/env bash
# scripts/generate-sbom.sh — Generate Software Bill of Materials for a release.
set -euo pipefail

mkdir -p dist

echo "Generating SBOM..."

cyclonedx-py environment \
    --output dist/sbom-python.json \
    --output-format json 2>/dev/null || true

cat > dist/sbom.json <<EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "boxmunge",
      "version": "$(python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")"
    }
  },
  "components": [
    {
      "type": "application",
      "name": "age",
      "version": "$(grep 'AGE_VERSION=' system/Dockerfile | head -1 | cut -d= -f2)"
    },
    {
      "type": "application",
      "name": "rclone",
      "version": "$(grep 'RCLONE_VERSION=' system/Dockerfile | head -1 | cut -d= -f2)"
    },
    {
      "type": "container",
      "name": "caddy",
      "version": "2-alpine"
    },
    {
      "type": "container",
      "name": "postgres",
      "version": "16-alpine"
    }
  ]
}
EOF

echo "SBOM written to dist/sbom.json"
