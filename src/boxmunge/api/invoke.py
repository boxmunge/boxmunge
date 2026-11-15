# SPDX-License-Identifier: Apache-2.0
"""invoke(): the one path every frontend takes to run an action.

1. Look up the action (unknown: not_found).
2. Check the principal's grant, then the tiers this server serves
   (forbidden).
3. Validate the parameters (invalid_params, listing every violation).
   A parameter marked x-tier raises the call's tier: check the grant and
   the served tiers again for that tier (forbidden, naming the parameter
   and the SSH command). Then run the action's param_check, if any
   (invalid_params with its message).
4. A plugin's operate call needs a verified approval (approval_required,
   approval_invalid). This build has no verifier, so none can pass.
5. For any tier but observe, write the "accepted" audit record; if it
   cannot be written, refuse with unavailable and run nothing.
6. Inline actions: take the locks, run the handler, validate its result.
7. For any tier but observe, write the outcome record.

A job action needs an Invoker made with jobs=True (unavailable otherwise).
After step 4 its project must exist (not_found) and no upgrade may hold the
jobs gate (unavailable, UPGRADE_REFUSAL). Then it gets an id, the accepted
record names that id, old jobs are pruned and the queued record is
published durably; a publish that fails with OSError is audited as failed
and refused as unavailable. invoke takes no lock for a job and writes no
outcome: the worker does both.

Every refusal in steps 1-4 is audited. A handler that hits unreadable box
state (PROJECT_INPUT_ERRORS) fails with `failed` and the reason; any other
exception is a bug and propagates to the caller after the outcome record.
"""
from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timezone
from typing import Any

from boxmunge.api.audit import AuditError, AuditLog, audit_record, redact
from boxmunge.api.actions._common import existing_project
from boxmunge.api.context import ActionContext, HostProbe
from boxmunge.api.job_gate import UPGRADE_REFUSAL, upgrade_holds_gate
from boxmunge.api.job_retention import prune
from boxmunge.api.job_writer import new_record, publish
from boxmunge.api.param_tiers import param_tier_refusal
from boxmunge.api.principal import Principal, PrincipalKind, Tier, refusal
from boxmunge.api.registry import Action, Registry
from boxmunge.api.result import ActionError, ActionResult, ErrorCode
from boxmunge.api.schema import validate
from boxmunge.fileutil import LockError, project_lock
from boxmunge.fleet import PROJECT_INPUT_ERRORS
from boxmunge.log import log_error
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.ulid import generate_ulid

ALL_TIERS = frozenset(Tier)
# A refused name is client-chosen; the audit log keeps only its head.
MAX_AUDITED_NAME = 128


class Invoker:
    def __init__(self, registry: Registry, paths: BoxPaths, host: HostProbe,
                 audit: AuditLog, *, served_tiers: frozenset[Tier] = ALL_TIERS,
                 jobs: bool = False) -> None:
        self._registry = registry
        self._paths = paths
        self._host = host
        self._audit = audit
        self._served = served_tiers
        self._jobs = jobs

    @property
    def paths(self) -> BoxPaths:
        return self._paths

    def catalog(self, principal: Principal) -> list[dict[str, Any]]:
        """Catalog entries for every action *principal* may call here."""
        return [a.catalog_entry() for a in self._registry.available_to(principal)
                if a.tier in self._served]

    def invoke(self, name: str, params: Any, principal: Principal,
               approval: dict[str, Any] | None = None) -> ActionResult:
        action = self._admit(name, params, principal, approval)
        safe_params = redact(action.params, params)
        if action.job:
            return self._publish(action, params, safe_params, principal)
        audited = action.tier is not Tier.OBSERVE
        if audited:
            self._accepted(principal, name, safe_params)
        try:
            data = self._run(action, params, principal)
        except ActionError as e:
            if audited:
                self._outcome(principal, name, safe_params, "failed", e.code.value, e.message)
            raise
        except BaseException as e:
            if audited:
                self._outcome(principal, name, safe_params, "failed", ErrorCode.FAILED.value,
                              f"internal error: {type(e).__name__}: {e}")
            raise
        if audited:
            self._outcome(principal, name, safe_params, "succeeded")
        return ActionResult(action=name, data=data)

    def _admit(self, name: str, params: Any, principal: Principal,
               approval: dict[str, Any] | None) -> Action:
        """Steps 1-4 and the job check: everything that refuses before running."""
        try:
            action = self._registry.get(name)
            why = refusal(principal, action.tier, agent_allowed=action.agent_allowed)
            if why is not None:
                raise ActionError(ErrorCode.FORBIDDEN, why)
            if action.tier not in self._served:
                raise ActionError(ErrorCode.FORBIDDEN,
                                  f"This server does not serve {action.tier.value} actions.")
            if not isinstance(params, dict):
                raise ActionError(ErrorCode.INVALID_PARAMS, "params must be a JSON object.")
            violations = validate(action.params, params)
            if violations:
                raise ActionError(ErrorCode.INVALID_PARAMS,
                                  f"Parameters for {name} do not match its schema.",
                                  {"violations": violations})
            why = param_tier_refusal(action, params, principal, self._served)
            if why is not None:
                raise ActionError(ErrorCode.FORBIDDEN, why)
            problem = action.param_check(params) if action.param_check else None
            if problem is not None:
                raise ActionError(ErrorCode.INVALID_PARAMS, problem)
            _check_approval(action, principal, approval)
            if action.job:
                self._check_job(action, params)
        except ActionError as e:
            self._refusal(principal, name, e)
            raise
        return action

    def _check_job(self, action: Action, params: dict[str, Any]) -> None:
        if not self._jobs:
            raise ActionError(ErrorCode.UNAVAILABLE,
                              f"{action.name} runs as a job, and this server has no job runner.")
        if "project" in params:
            existing_project(self._paths, params["project"])
        if upgrade_holds_gate(self._paths):
            raise ActionError(ErrorCode.UNAVAILABLE, UPGRADE_REFUSAL)

    def _accepted(self, principal: Principal, name: str, params: dict[str, Any],
                  job: str | None = None) -> None:
        """The accepted record; unavailable (and nothing runs) if it cannot be written."""
        try:
            self._audit.append(audit_record(principal.id, name, "accepted",
                                            params=params, job=job))
        except AuditError as e:
            log_error("audit", f"refused {name} for {principal.id}: {e}", self._paths)
            raise ActionError(
                ErrorCode.UNAVAILABLE,
                f"The audit log cannot be written, so {name} did not run: {e}",
            ) from e

    def _publish(self, action: Action, params: dict[str, Any], safe_params: dict[str, Any],
                 principal: Principal) -> ActionResult:
        """Queue a job action durably and return its record."""
        name = action.name
        job_id = generate_ulid()
        self._accepted(principal, name, safe_params, job=job_id)
        now = datetime.now(timezone.utc)
        record = new_record(job_id, name, params, principal.id, params.get("project"), now)
        try:
            prune(self._paths, now)
            published = publish(self._paths, record)
        except OSError as e:
            error = ActionError(ErrorCode.UNAVAILABLE,
                                f"Job {job_id} for {name} could not be queued, so it will not "
                                f"run: {e}. Fix the cause, then make the call again.")
            self._outcome(principal, name, safe_params, "failed", error.code.value,
                          error.message, job=job_id)
            raise error from e
        except BaseException as e:
            self._outcome(principal, name, safe_params, "failed", ErrorCode.FAILED.value,
                          f"internal error: {type(e).__name__}: {e}", job=job_id)
            raise
        if not published:
            message = (f"Job id {job_id} for {name} is already taken. This is a boxmunge "
                       f"bug; please report it.")
            self._outcome(principal, name, safe_params, "failed", ErrorCode.FAILED.value,
                          message, job=job_id)
            raise ActionError(ErrorCode.FAILED, message)
        return ActionResult(action=name, data=record, job=True)

    def _run(self, action: Action, params: dict[str, Any],
             principal: Principal) -> dict[str, Any]:
        ctx = ActionContext(principal=principal, paths=self._paths, host=self._host,
                            result_schemas=self._result_schema_of)
        with ExitStack() as stack:
            if "project" in action.locks:
                project = params["project"]
                try:
                    stack.enter_context(project_lock(project, self._paths))
                except LockError as e:
                    raise ActionError(ErrorCode.BUSY, str(e),
                                      {"lock": "project", "project": project}) from e
            try:
                data = action.handler(params, ctx)
            except PROJECT_INPUT_ERRORS as e:
                raise ActionError(ErrorCode.FAILED, str(e)) from e
        violations = validate(action.result, data, result_schemas=self._result_schema_of)
        if violations:
            log_error("api", f"{action.name} returned a result outside its schema",
                      self._paths, detail={"violations": violations})
            raise ActionError(
                ErrorCode.FAILED,
                f"{action.name} returned a result that does not match its schema. "
                f"This is a boxmunge bug; please report it.",
                {"violations": violations[:20]},
            )
        return data

    def _result_schema_of(self, name: str) -> dict[str, Any] | None:
        """The result schema of action *name*, for x-result-of-action."""
        try:
            return self._registry.get(name).result
        except ActionError:
            return None

    def _refusal(self, principal: Principal, name: str, error: ActionError) -> None:
        record = audit_record(principal.id, _audited_name(name), "refused",
                              code=error.code.value, message=error.message)
        try:
            self._audit.append(record)
        except AuditError as e:
            log_error("audit", f"could not record the refusal of {name} for "
                      f"{principal.id}: {e}", self._paths)

    def _outcome(self, principal: Principal, name: str, params: dict[str, Any],
                 outcome: str, code: str | None = None, message: str | None = None,
                 job: str | None = None) -> None:
        record = audit_record(principal.id, name, outcome, params=params,
                              code=code, message=message, job=job)
        try:
            self._audit.append(record)
        except AuditError as e:
            log_error("audit", f"could not record the outcome of {name}: {e}",
                      self._paths, detail={"outcome": outcome, "principal": principal.id})
            notify(self._paths, "boxmunge: audit log write failed",
                   f"The outcome ({outcome}) of {name} by {principal.id} was not "
                   f"recorded: {e}", component="audit", priority=1)


def _audited_name(name: str) -> str:
    if len(name) <= MAX_AUDITED_NAME:
        return name
    return f"{name[:MAX_AUDITED_NAME]}...({len(name) - MAX_AUDITED_NAME} more characters)"


def _check_approval(action: Action, principal: Principal,
                    approval: dict[str, Any] | None) -> None:
    needs_approval = principal.kind is PrincipalKind.PLUGIN and action.tier is Tier.OPERATE
    if not needs_approval:
        if approval is not None:
            raise ActionError(ErrorCode.INVALID_PARAMS,
                              "approval is accepted only on operate calls from plugins.")
        return
    if approval is None:
        raise ActionError(ErrorCode.APPROVAL_REQUIRED,
                          f"{action.name} needs the operator's approval for this call.")
    raise ActionError(ErrorCode.APPROVAL_INVALID,
                      "This server cannot verify approvals, so no operate call from a "
                      "plugin can run.")
