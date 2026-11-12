# SPDX-License-Identifier: Apache-2.0
"""boxmunge upgrade-readiness [--json]: is this box ready for this release?

The upgrade check (the root shim's `check` verb, which deploy reaches as
`upgrade-check`) runs the *target* release's copy of this command, as deploy
and confined, against the live box. An operator can run the installed
release's copy by hand (boxmunge.readiness says what it may touch then).

Exit 0 pass, 1 blocked, 2 usage error. With --json, stdout is exactly one
contract-1 object (boxmunge.readiness_contract): whatever the rules print on
the way goes to stderr.
"""
from __future__ import annotations

import json
import sys
from contextlib import redirect_stdout

from boxmunge.commands.argv import parse_args
from boxmunge.paths import BoxPaths
from boxmunge.readiness import evaluate
from boxmunge.readiness_contract import Finding, Readiness, to_json

_SEVERITY = {"block": "BLOCK", "todo": "TO DO"}


def _finding_lines(f: Finding, indent: str) -> list[str]:
    return [f"{indent}{_SEVERITY[f.severity]} ({f.when} the upgrade) {f.id}: {f.message}",
            f"{indent}  fix: {f.remedy}"]


def render_text(r: Readiness) -> str:
    """The operator's view: the verdict, the box, then each project."""
    lines = [f"Upgrade readiness for boxmunge {r.release} (this box records "
             f"{r.installed}): {r.result.upper()}", "", "Box:"]
    lines += [line for f in r.box for line in _finding_lines(f, "  ")] or ["  ready"]
    lines += ["", "Projects:"]
    for project in r.projects:
        lines.append(f"  {project.name}: {project.result}"
                     + ("" if project.findings else ", nothing to do"))
        lines += [line for f in project.findings for line in _finding_lines(f, "    ")]
    if not r.projects:
        lines.append("  none")
    if r.result == "blocked":
        lines += ["", "BLOCK findings stop an upgrade to this release; TO DO findings are "
                      "what each project's next deploy needs."]
    return "\n".join(lines)


def cmd_upgrade_readiness(args: list[str]) -> None:
    parsed = parse_args("upgrade-readiness", args, flags={"--json"})
    with redirect_stdout(sys.stderr):
        readiness = evaluate(BoxPaths())
    print(json.dumps(to_json(readiness)) if parsed.has("--json") else render_text(readiness))
    sys.exit(0 if readiness.result == "pass" else 1)
