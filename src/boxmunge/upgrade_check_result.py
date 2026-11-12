# SPDX-License-Identifier: Apache-2.0
"""The upgrade shim's readiness-check verdict, read and shown on the deploy side.

`boxmunge-upgrade check <version>` (root, through sudo) prints one JSON
object, check contract 1:

    {"check": 1, "target", "installed", "result": pass|blocked|cant_verify,
     "stage", "reasons": [str], "prerequisites": [{script, ok, message}],
     "readiness": <readiness contract 1> | null,
     "dry_run": {"ok": bool, "output": str} | null}

It is read failing closed: anything outside that shape, a verdict for
another release than the one asked for, a readiness answer from another
release (a signed older bundle served under the target's name), or a pass
that its own parts or exit code contradict is "can't verify" here, at the
deploy-side stage "shim", never a pass. Keys it does not know are ignored.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from boxmunge.readiness_contract import ContractError, Finding, Readiness, parse, to_json
from boxmunge.upgrade_shim import printable, printable_lines, stderr_tail, sudo_refusal

CHECK_CONTRACT = 1
RESULTS = ("pass", "blocked", "cant_verify")
STAGES = ("refused", "fetch", "prerequisites", "venv", "readiness", "dry_run", "complete")
NO_VERDICT_STAGE = "shim"  # the deploy side's own: the shim gave no usable verdict
_SHOWN = {"pass": "PASS", "blocked": "BLOCKED", "cant_verify": "CAN'T VERIFY"}
_RELEASE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")


@dataclass(frozen=True)
class CheckResult:
    target: str
    installed: str
    result: str
    stage: str
    reasons: tuple[str, ...]
    prerequisites: tuple[dict, ...]
    readiness: Readiness | None
    dry_run_ok: bool | None
    dry_run_output: str


class _Unreadable(ValueError):
    """The verdict is outside check contract 1."""


def _no_verdict(target: str, installed: str, reason: str) -> CheckResult:
    return CheckResult(target, installed, "cant_verify", NO_VERDICT_STAGE, (reason,), (),
                       None, None, "")


def _field(doc: dict, key: str, ok: Any, what: str) -> Any:
    if key not in doc or not ok(doc[key]):
        raise _Unreadable(f"{key} must be {what}, not {doc.get(key, '(missing)')!r}"[:300])
    return doc[key]


def _is_text_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def _is_prerequisite(p: Any) -> bool:
    return (isinstance(p, dict) and isinstance(p.get("script"), str)
            and type(p.get("ok")) is bool and isinstance(p.get("message"), str))


def _is_dry_run(d: Any) -> bool:
    return d is None or (isinstance(d, dict) and type(d.get("ok")) is bool
                         and isinstance(d.get("output"), str))


def _read(doc: dict) -> CheckResult:
    """A check-contract-1 object as a CheckResult; raises _Unreadable or
    ContractError (the embedded readiness answer)."""
    _field(doc, "check", lambda v: type(v) is int and v == CHECK_CONTRACT, "1")
    release = (lambda v: isinstance(v, str) and _RELEASE.fullmatch(v) is not None)
    target = _field(doc, "target", release, "a release")
    installed = _field(doc, "installed", release, "a release")
    result = _field(doc, "result", lambda v: v in RESULTS, " or ".join(RESULTS))
    stage = _field(doc, "stage", lambda v: v in STAGES, " or ".join(STAGES))
    reasons = _field(doc, "reasons", _is_text_list, "a list of strings")
    prerequisites = _field(doc, "prerequisites",
                           lambda v: isinstance(v, list) and all(map(_is_prerequisite, v)),
                           "a list of {script, ok, message}")
    dry_run = _field(doc, "dry_run", _is_dry_run, "null or {ok, output}")
    raw_readiness = _field(doc, "readiness", lambda v: True, "null or a readiness answer")
    readiness = None if raw_readiness is None else parse(raw_readiness)
    return CheckResult(target, installed, result, stage, tuple(reasons),
                       tuple({k: p[k] for k in ("script", "ok", "message")}
                             for p in prerequisites),
                       readiness, None if dry_run is None else dry_run["ok"],
                       "" if dry_run is None else dry_run["output"])


def _contradiction(r: CheckResult, target: str, returncode: int) -> str | None:
    """Why a well-formed verdict still cannot be believed, or None."""
    if r.target != target:
        return f"the verdict is for release {r.target}, not {target}, the release asked for"
    if r.readiness is not None and r.readiness.release != target:
        return (f"the readiness check that ran was release {r.readiness.release}'s, not "
                f"{target}'s: the bundle served for {target} is another release's")
    if (returncode == 0) != (r.result == "pass"):
        return (f"the upgrade shim exited {returncode}, which contradicts its result, "
                f"{r.result}")
    if r.result == "pass" and r.stage != "complete":
        return f"the upgrade shim said pass at stage {r.stage}, before the check completed"
    if r.result == "pass" and not (
            all(p["ok"] for p in r.prerequisites) and r.readiness is not None
            and r.readiness.result == "pass" and r.dry_run_ok is True):
        return ("the upgrade shim said pass, but its prerequisites, readiness answer or "
                "dry run do not all pass")
    return None


def parse_check(stdout: str, stderr: str, returncode: int, *, target: str,
                installed: str) -> CheckResult:
    """The verdict of `boxmunge-upgrade check <target>`, from what it printed
    and its exit code. Never raises: what cannot be read is can't verify."""
    try:
        doc = json.loads(stdout)
    except (ValueError, RecursionError):
        doc = None
    if not isinstance(doc, dict) or "check" not in doc:
        hint = sudo_refusal(stderr)
        return _no_verdict(target, installed, "the upgrade shim gave no verdict: "
                           + stderr_tail(stderr) + (f". {hint}" if hint else ""))
    try:
        r = _read(doc)
    except (_Unreadable, ContractError) as e:
        return _no_verdict(target, installed,
                           f"the upgrade shim's verdict is not one this release reads: {e}")
    problem = _contradiction(r, target, returncode)
    if problem is not None:
        return _no_verdict(target, r.installed,
                           f"the upgrade shim's verdict cannot be used: {problem}")
    return r


def exit_code(r: CheckResult) -> int:
    return 0 if r.result == "pass" else 1


def _item(first: str, text: str, indent: str) -> list[str]:
    """`first`, then `text`, whose further lines keep `indent`: nothing the
    verdict carries can start a line of its own (a forged result line)."""
    head, *rest = printable_lines(text)
    return [first + head, *(indent + line for line in rest)]


def _one_line(text: str) -> str:
    return " ".join(printable_lines(text))


def _finding_lines(f: Finding, indent: str) -> list[str]:
    return (_item(f"{indent}[{f.severity}, {f.when}] {_one_line(f.id)}: ", f.message,
                  indent + "    ")
            + _item(f"{indent}    Fix: ", f.remedy, indent + "         "))


def _box_lines(r: CheckResult) -> list[str]:
    lines = [line for p in r.prerequisites
             for line in (_item(f"  {_one_line(p['script'])}: NOT MET: ", p["message"], "    ")
                          if not p["ok"] else [f"  {_one_line(p['script'])}: met"])]
    if r.readiness is not None:
        lines += [line for f in r.readiness.box for line in _finding_lines(f, "  ")]
    return lines or ["  nothing to report"]


def _project_lines(r: CheckResult) -> list[str]:
    if r.readiness is None:
        why = ("this box does not meet a prerequisite of the release (see Box)"
               if r.stage == "prerequisites" else
               f"the check stopped before the readiness check ({r.stage})")
        return [f"  not checked: {why}"]
    lines: list[str] = []
    for project in r.readiness.projects:
        lines.append(f"  {_one_line(project.name)}: {project.result}"
                     + ("" if project.findings else ", nothing to do"))
        lines += [line for f in project.findings for line in _finding_lines(f, "    ")]
    return lines or ["  none on this box"]


def render_check(r: CheckResult) -> str:
    """The verdict as text: result, reasons, box, every project, then what
    to do. Printable characters and newlines only, and only the first and
    last lines start with "Result"."""
    lines = [f"Result: {_SHOWN[r.result]} ({r.stage})",
             f"Checked: an upgrade from {r.installed} to {r.target}", ""]
    if r.reasons:
        lines += ["Why:", *(line for reason in r.reasons for line in _item("  - ", reason,
                                                                         "    ")), ""]
    lines += ["Box:", *_box_lines(r), "", "Projects:", *_project_lines(r), ""]
    if r.dry_run_ok is False:
        lines += ["The upgrade's own pre-flight (upgrade --dry-run) ended with:",
                  *(f"  {line}" for line in printable_lines(r.dry_run_output)), ""]
    if r.result == "pass":
        lines.append(f"Result is PASS: the upgrade command is: upgrade --target {r.target}")
    else:
        lines.append("Result is not PASS: do not upgrade. Report this to the person, "
                     "per project.")
    return "\n".join(lines)


def _clean(value: Any) -> Any:
    if isinstance(value, str):
        return printable(value)
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    return value


def check_to_json(r: CheckResult) -> dict[str, Any]:
    """The verdict as check contract 1 again (`upgrade-check --json`)."""
    return _clean({
        "check": CHECK_CONTRACT, "target": r.target, "installed": r.installed,
        "result": r.result, "stage": r.stage, "reasons": list(r.reasons),
        "prerequisites": [dict(p) for p in r.prerequisites],
        "readiness": None if r.readiness is None else to_json(r.readiness),
        "dry_run": None if r.dry_run_ok is None else {"ok": r.dry_run_ok,
                                                      "output": r.dry_run_output}})
