# SPDX-License-Identifier: Apache-2.0
"""invoke(): the one path every frontend takes to run an action.

1. Look up the action (unknown: not_found).
2. Check the principal's grant, then the tiers this server serves
   (forbidden).
3. Validate the parameters (invalid_params, listing every violation).
4. A plugin's operate call needs a verified approval (approval_required,
   approval_invalid). This build has no verifier, so none can pass.
5. For any tier but observe, write the "accepted" audit record; if it
   cannot be written, refuse with unavailable and run nothing.
6. Inline actions: take the locks, run the handler, validate its result.
   Job actions need a job runner, which this build does not have.
7. For any tier but observe, write the outcome record.

Every refusal in steps 1-4 is audited. A handler that hits unreadable box
state (PROJECT_INPUT_ERRORS) fails with `failed` and the reason; any other
exception is a bug and propagates to the caller after the outcome record.
"""
from __future__ import annotations

from contextlib import ExitStack
from typing import Any

from boxmunge.api.audit import AuditError, AuditLog, audit_record, redact
from boxmunge.api.context import ActionContext, HostProbe
from boxmunge.api.principal import Principal, PrincipalKind, Tier, refusal
from boxmunge.api.registry import Action, Registry
from boxmunge.api.result import ActionError, ActionResult, ErrorCode
from boxmunge.api.schema import validate
from boxmunge.fileutil import LockError, project_lock
from boxmunge.fleet import PROJECT_INPUT_ERRORS
from boxmunge.log import log_error
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths

ALL_TIERS = frozenset(Tier)
# A refused name is client-chosen; the audit log keeps only its head.
MAX_AUDITED_NAME = 128


class Invoker:
    def __init__(self, registry: Registry, paths: BoxPaths, host: HostProbe,
                 audit: AuditLog, *, served_tiers: frozenset[Tier] = ALL_TIERS) -> None:
        self._registry = registry
        self._paths = paths
        self._host = host
        self._audit = audit
        self._served = served_tiers

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
        audited = action.tier is not Tier.OBSERVE
        safe_params = redact(action.params, params)
        if audited:
            try:
                self._audit.append(audit_record(principal, name, "accepted", params=safe_params))
            except AuditError as e:
                log_error("audit", f"refused {name} for {principal.id}: {e}", self._paths)
                raise ActionError(
                    ErrorCode.UNAVAILABLE,
                    f"The audit log cannot be written, so {name} did not run: {e}",
                ) from e
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
            _check_approval(action, principal, approval)
            if action.job:
                raise ActionError(ErrorCode.UNAVAILABLE,
                                  f"{name} runs as a job, and this server has no job runner.")
        except ActionError as e:
            self._refusal(principal, name, e)
            raise
        return action

    def _run(self, action: Action, params: dict[str, Any],
             principal: Principal) -> dict[str, Any]:
        ctx = ActionContext(principal=principal, paths=self._paths, host=self._host)
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
        violations = validate(action.result, data)
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

    def _refusal(self, principal: Principal, name: str, error: ActionError) -> None:
        record = audit_record(principal, _audited_name(name), "refused",
                              code=error.code.value, message=error.message)
        try:
            self._audit.append(record)
        except AuditError as e:
            log_error("audit", f"could not record the refusal of {name} for "
                      f"{principal.id}: {e}", self._paths)

    def _outcome(self, principal: Principal, name: str, params: dict[str, Any],
                 outcome: str, code: str | None = None, message: str | None = None) -> None:
        record = audit_record(principal, name, outcome, params=params,
                              code=code, message=message)
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
