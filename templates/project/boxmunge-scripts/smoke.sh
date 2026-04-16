#!/usr/bin/env bash
# Smoke test for __PROJECT_NAME__
#
# Exit codes:
#   0 = healthy
#   1 = warning/error (alerts after threshold consecutive failures)
#   2 = critical (alerts immediately, stops containers)
#
# Write exactly ONE line to stderr for the alert message.
# See /opt/boxmunge/docs/PROJECT_CONVENTIONS.md for full contract.

set -euo pipefail

# TODO: Replace with actual health checks for your project.

# Example: check frontend responds
# if ! curl -sf http://localhost:3000/ > /dev/null 2>&1; then
#     echo "Frontend not responding" >&2
#     exit 1
# fi

echo "No smoke checks configured yet" >&2
exit 1
