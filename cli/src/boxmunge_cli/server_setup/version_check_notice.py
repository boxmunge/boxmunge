# SPDX-License-Identifier: Apache-2.0
"""The version-check explanation shown before 'Are you sure?'.

Kept identical to boxmunge.version_check_notice.NOTICE in the server package
(tests/test_version_check_notice.py in the server repo checks it), because the
CLI is released separately and cannot import the server.
"""

NOTICE = """\
boxmunge's version-check service (boxmunge.dev)

What it sends: every 6 hours, and on a plain `upgrade`, the box asks for
/v1/check?v=<installed version> with User-Agent boxmunge/<installed version>.
When an upgrade fails, it also reports the version it tried, the version it
came from, the step that failed and a short reason. No hostname, machine ID or
project names. Like any connection, both carry the box's IP address.

What it keeps: in its database, the network prefix the request came from
(IPv4 /24, IPv6 /48), not the full address, with the version and the date (a
failure report is kept with the prefix and the time it arrived), deleted after
90 days; and a daily count of checks per version. A prefix is not anonymous: a
/48 is often one household or company. Elsewhere full IP addresses are kept:
the request logs of the web server and of the service itself, until they
rotate, and encrypted database backups until they expire (the oldest hold full
addresses of failure reporters).

Why: so the maintainer can see which networks still run an old release, and
can hold a release when upgrades to it fail on several networks.

If you decline: with version_check.enabled: false the box discovers no
releases, so security and break-fix releases are not installed automatically.
`health` and `doctor` warn. You then watch https://github.com/boxmunge/boxmunge/releases
and run `upgrade --target X.Y.Z` yourself.

Full details: "What boxmunge sends home" in `agent-help operations`, and
https://boxmunge.dev/#privacy.
"""
