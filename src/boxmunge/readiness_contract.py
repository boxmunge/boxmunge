# SPDX-License-Identifier: Apache-2.0
"""The readiness JSON, contract 1: what `upgrade-readiness --json` prints.

The upgrade check runs the *target* release's `upgrade-readiness --json` and
parses its output with the *installed* release's parse(). So every release
from 0.11.8 on prints contract 1 (tests/fixtures/readiness_contract_v1.json
pins it), and parse() fails closed: an unknown contract, result, severity or
`when`, a missing key or a wrong type is a ContractError, which the caller
reports as "can't verify", never as a pass. Unknown keys are ignored, so a
later release may add keys without a new contract; a new severity or result
value needs contract 2.

The readiness command reports only `pass` or `blocked`. "Can't verify"
belongs to the callers (the shim and the deploy side).

`installed` is "0.0.0" when the box records no release it can read
(config/version missing or malformed): "not recorded", never a release.
It always comes with a box.upgrade_floor block that says so.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

CONTRACT_VERSION = 1
SEVERITIES = ("block", "todo")
WHENS = ("before", "after")
RESULTS = ("pass", "blocked")

# A release as the shim's SEMVER_RE reads it: X.Y.Z, optionally -pre, never +build.
_SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")


class ContractError(ValueError):
    """A readiness document (or a value meant for one) is outside contract 1."""


def _text(value: object, what: str, *, empty: bool = True) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise ContractError(f"{what} must be {'a' if empty else 'a non-empty'} string, "
                            f"not {value!r}")
    return value


def _one_of(value: object, allowed: tuple[str, ...], what: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ContractError(f"{what} must be one of {', '.join(allowed)}, not {value!r}")
    return value


def _semver(value: object, what: str) -> str:
    if not isinstance(value, str) or _SEMVER.fullmatch(value) is None:
        raise ContractError(f"{what} must be a release like 0.12.0, not {value!r}")
    return value


def _result(findings: tuple[Finding, ...]) -> str:
    return "blocked" if any(f.severity == "block" for f in findings) else "pass"


@dataclass(frozen=True)
class Finding:
    """One rule's finding: `block` stops the upgrade, `todo` is work for the
    project's next deploy. `when`: before or after the box upgrade."""
    id: str
    severity: str
    when: str
    message: str
    remedy: str

    def __post_init__(self) -> None:
        _text(self.id, "a finding's id", empty=False)
        _one_of(self.severity, SEVERITIES, f"{self.id}: severity")
        _one_of(self.when, WHENS, f"{self.id}: when")
        _text(self.message, f"{self.id}: message")
        _text(self.remedy, f"{self.id}: remedy")


@dataclass(frozen=True)
class ProjectReadiness:
    name: str
    findings: tuple[Finding, ...]

    def __post_init__(self) -> None:
        _text(self.name, "a project's name", empty=False)

    @property
    def result(self) -> str:
        return _result(self.findings)


@dataclass(frozen=True)
class Readiness:
    """The box and every project, against the rules of release `release`;
    `installed` is the release the box records (config/version)."""
    release: str
    installed: str
    box: tuple[Finding, ...]
    projects: tuple[ProjectReadiness, ...]

    def __post_init__(self) -> None:
        _semver(self.release, "release")
        _semver(self.installed, "installed")

    @property
    def result(self) -> str:
        return _result(self.box + tuple(f for p in self.projects for f in p.findings))


def _finding_json(f: Finding) -> dict[str, str]:
    return {"id": f.id, "severity": f.severity, "when": f.when,
            "message": f.message, "remedy": f.remedy}


def to_json(r: Readiness) -> dict[str, Any]:
    """The contract-1 document for `r`."""
    return {
        "contract": CONTRACT_VERSION, "release": r.release, "installed": r.installed,
        "result": r.result,
        "box": [_finding_json(f) for f in r.box],
        "projects": [{"name": p.name, "result": p.result,
                      "findings": [_finding_json(f) for f in p.findings]}
                     for p in r.projects],
    }


def _object(value: object, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{what} must be a JSON object, not {type(value).__name__}")
    return value


def _key(doc: dict[str, Any], key: str, what: str) -> Any:
    if key not in doc:
        raise ContractError(f"{what} has no {key!r}")
    return doc[key]


def _list(doc: dict[str, Any], key: str, what: str) -> list[Any]:
    value = _key(doc, key, what)
    if not isinstance(value, list):
        raise ContractError(f"{what}: {key!r} must be a list, not {type(value).__name__}")
    return value


def _parse_finding(value: object, what: str) -> Finding:
    doc = _object(value, what)
    return Finding(*(_key(doc, key, what) for key in ("id", "severity", "when",
                                                      "message", "remedy")))


def _parse_project(value: object, index: int) -> ProjectReadiness:
    what = f"projects[{index}]"
    doc = _object(value, what)
    project = ProjectReadiness(
        _key(doc, "name", what),
        tuple(_parse_finding(f, f"{what}.findings[{i}]")
              for i, f in enumerate(_list(doc, "findings", what))))
    _agrees(_key(doc, "result", what), project.result, f"{what} ({project.name})")
    return project


def _agrees(stated: object, computed: str, what: str) -> None:
    """A stated result must be a known one and the one its findings give."""
    if _one_of(stated, RESULTS, f"{what}: result") != computed:
        raise ContractError(f"{what}: result is {stated!r}, but its findings make it "
                            f"{computed!r}")


def parse(doc: object) -> Readiness:
    """The Readiness in a contract-1 document (already decoded from JSON).
    Raises ContractError for anything outside contract 1."""
    top = _object(doc, "the readiness document")
    contract = _key(top, "contract", "the readiness document")
    if type(contract) is not int or contract != CONTRACT_VERSION:
        raise ContractError(f"contract {contract!r} is not contract {CONTRACT_VERSION}")
    readiness = Readiness(
        release=_key(top, "release", "the readiness document"),
        installed=_key(top, "installed", "the readiness document"),
        box=tuple(_parse_finding(f, f"box[{i}]")
                  for i, f in enumerate(_list(top, "box", "the readiness document"))),
        projects=tuple(_parse_project(p, i)
                       for i, p in enumerate(_list(top, "projects", "the readiness document"))),
    )
    _agrees(_key(top, "result", "the readiness document"), readiness.result,
            "the readiness document")
    return readiness
