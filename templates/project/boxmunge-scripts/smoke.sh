#!/bin/sh
# Smoke test for __PROJECT_NAME__
#
# boxmunge runs it inside each container of every service whose manifest
# entry names it in `smoke:`, as `sh /boxmunge-scripts/smoke.sh <service>`,
# after each deploy and on every health check. POSIX sh only: the
# container's /bin/sh may be dash or busybox, not bash. It can use only the
# tools inside the container.
#
# Exit codes:
#   0 = healthy
#   1 = warning (alerts after health.alert_threshold failures in a row)
#   2 = critical (alerts at once and stops every container in the project)
#
# Write exactly ONE line to stderr for the alert message.
# Full contract: run 'agent-help conventions' on the server.
set -u

# TODO: Replace with actual health checks for your project.

# Example: check frontend responds
# if ! wget -q -O /dev/null -T 5 http://127.0.0.1:3000/; then
#     echo "Frontend not responding" >&2
#     exit 1
# fi

echo "No smoke checks configured yet" >&2
exit 1
