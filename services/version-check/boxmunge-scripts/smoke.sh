#!/usr/bin/env sh
# Verify the service is up. /healthz is not counted in the check statistics;
# /v1/check is, so a smoke test that called it would drown the real numbers.
# Uses python (always available in this image) — alpine slim doesn't ship curl.
# The smoke test runs inside the project's docker compose network.
# Compose service name (from compose.yml) is "web" — that's the DNS name
# other containers use to reach this service.
set -eu

python3 -c "
import sys, json, urllib.request
try:
    with urllib.request.urlopen('http://web:8147/healthz', timeout=5) as r:
        data = json.loads(r.read())
except Exception as e:
    print(f'FAIL: /healthz endpoint unreachable: {e}', file=sys.stderr)
    sys.exit(1)
if data.get('status') != 'ok':
    print(f'FAIL: /healthz did not report ok: {data}', file=sys.stderr)
    sys.exit(1)
print('OK: version-check service healthy')
"
