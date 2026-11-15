# SPDX-License-Identifier: Apache-2.0
"""Pieces the operate families share: running a lock-free core as a job,
the parameters those actions have in common, and the Action they make.

An operate action is a job over one of the platform's `*_locked` cores.
The job worker takes the project lock and captures the core's output (the
job's events); the handler never takes the lock. A core reports through
its output and exit status, so a non-zero exit becomes CoreFailed, which
the worker turns into the job's failure message (job_capture).

Everyday flags are exposed as they are. A flag that weakens a control
(deploying past the security regression guard, accepting a stale KEV
listing) carries x-tier govern, so the call needs govern (param_tiers).
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from boxmunge.api.actions._common import PROJECT_PARAM
from boxmunge.api.job_capture import CoreFailed
from boxmunge.api.principal import Tier
from boxmunge.api.registry import Action, Handler, ParamCheck
from boxmunge.api.schema import BOOLEAN, obj
from boxmunge.commands.security_regression_guard import regression_override
from boxmunge.paths import BoxPaths

PROJECT = PROJECT_PARAM
ALLOW_REGRESSION: dict[str, Any] = {
    "type": "string", "minLength": 1, "maxLength": 500, "x-tier": "govern",
    "description": "Deploy despite the security regression guard; the reason is logged "
                   "and alerted (--allow-security-regression --reason).",
}
NO_PULL: dict[str, Any] = {
    **BOOLEAN,
    "description": "Build from the base images in the box's local image store instead "
                   "of pulling their current digests (--no-pull).",
}
REF: dict[str, Any] = {"type": "string", "minLength": 1, "maxLength": 200}


def run_core(verb: str, call: Callable[[], int]) -> None:
    """Run a core; CoreFailed(verb, rc) unless it exits 0. *verb* is the
    CLI command the core backs, which the job's failure message names."""
    rc = call()
    if rc != 0:
        raise CoreFailed(verb, rc)


def non_blank(*names: str) -> ParamCheck:
    """A param_check refusing any of *names* given as only whitespace: a
    reason that is logged and alerted must say something."""
    def check(params: dict[str, Any]) -> str | None:
        blank = [name for name in names if name in params and not params[name].strip()]
        if not blank:
            return None
        return (f"{blank[0]} is blank: give the reason in words; it is logged and "
                f"alerted.")
    return check


@contextmanager
def regression_allowed(paths: BoxPaths, params: dict[str, Any]) -> Iterator[None]:
    """The security regression guard's override for one call: the reason
    given as allow_security_regression (stripped), or none."""
    reason = params.get("allow_security_regression")
    with regression_override(paths, params["project"],
                             None if reason is None else reason.strip()):
        yield


def operate_job(name: str, summary: str, *, params: dict[str, dict[str, Any]],
                result: dict[str, Any], handler: Handler, cli: str,
                param_check: ParamCheck | None = None) -> Action:
    """An operate action run as a job under the project lock. *params* are
    the properties besides project, all optional. An
    allow_security_regression among them must not be blank; *param_check*
    is any further check, run after that one."""
    if "project" in params:
        raise ValueError(f"{name}: operate_job adds the project parameter itself")
    checks = [check for check in (
        non_blank("allow_security_regression") if "allow_security_regression" in params
        else None, param_check) if check is not None]
    return Action(
        name=name, tier=Tier.OPERATE, summary=summary,
        params=obj({"project": PROJECT, **params}, optional=tuple(params)),
        result=result, handler=handler, locks=("project",), job=True, cli=cli,
        param_check=_first_problem(checks) if checks else None,
    )


def _first_problem(checks: list[ParamCheck]) -> ParamCheck:
    def check(params: dict[str, Any]) -> str | None:
        return next((problem for c in checks if (problem := c(params)) is not None), None)
    return check
