#!/usr/bin/env bash
# TODO: Update with a real health check for your service.
set -euo pipefail

response=$(curl -sf http://localhost:8080/ || true)
if [ -z "$response" ]; then
  echo "FAIL: no response from web service"
  exit 1
fi
echo "OK"
