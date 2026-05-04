#!/usr/bin/env sh
# Verify the version-check endpoint responds with valid JSON.
# Uses python (always available in this image) — alpine slim doesn't ship curl.
# The smoke test runs inside the project's docker compose network.
# Compose service name (from compose.yml) is "web" — that's the DNS name
# other containers use to reach this service.
set -eu

python3 -c "
import sys, json, urllib.request
try:
    with urllib.request.urlopen('http://web:8147/v1/check?v=0.0.0', timeout=5) as r:
        data = json.loads(r.read())
except Exception as e:
    print(f'FAIL: /v1/check endpoint unreachable: {e}', file=sys.stderr)
    sys.exit(1)
for k in ('status', 'security', 'latest'):
    if k not in data:
        print(f'FAIL: /v1/check response missing {k} field', file=sys.stderr)
        sys.exit(1)
print('OK: version-check service healthy')
"
