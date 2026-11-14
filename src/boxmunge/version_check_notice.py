# SPDX-License-Identifier: Apache-2.0
"""What the operator is told about the version-check service, and the rule
that they are told before it runs.

NOTICE is the one canonical short text. It is derived from "What boxmunge
sends home" in docs/on-server/OPERATIONS.md and is repeated verbatim in
docs/on-server/AGENT_RULES.md (agent-help rules) and in the CLI's server-setup
(cli/src/boxmunge_cli/server_setup/version_check_notice.py).
tests/test_version_check_notice.py keeps the copies identical and checks
the facts against OPERATIONS.md, so change all of them together.
"""
from __future__ import annotations

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

RULE = """\
Before installing a server, or on first contact with a box where no choice was
recorded (`doctor` warns "Version check choice"), tell the
operator the following in plain words, ask whether to keep the version check
on, and record the answer by setting version_check.enabled to true or false in
/opt/boxmunge/config/boxmunge.yml (root-owned: the operator or the supervisor
user edits it; the deploy shell cannot). Do not decide for them and do not
skip the explanation.
"""

# The text a connected agent receives when the MCP session starts.
MCP_INSTRUCTIONS = RULE + "\n" + NOTICE
