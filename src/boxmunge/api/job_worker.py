# SPDX-License-Identifier: Apache-2.0
"""The job worker: `boxmunge-server _run-job <id>` runs one queued job.

1. Hold the jobs gate shared for the whole job. A worker that had to wait
   for it (an upgrade held it) leaves the job queued and exits EX_TEMPFAIL,
   so the job runs on the code the upgrade installed, never the old code.
2. Claim the job durably; a job that is not queued is not ours (exit 1).
3. Open its event log; check the action and parameters still hold on the
   code installed now.
4. With fds 1 and 2 captured as log events, wait up to
   JOB_LOCK_WAIT_SECONDS for each lock, then run the handler. A lock held
   for the whole wait fails the job `busy` before any handler code runs.
5. Release the locks, then run what the handler left for after_release.
6. Check the result, finish the record, write the terminal state event and
   the outcome audit record.

The outcome audit record is written strictly after finish has moved the
record out of the queue. A worker that dies mid-move has its outcome line
written by the runner, which completes the move. One that dies after the
move but before its append leaves the outcome in the job record only: a
known, narrow window in which the audit log shows just the accepted line.

A SIGTERM (Terminated) fails the job, alerts its way out, and is raised
again so the process ends as stopped. Exits 0 once the job is terminal.
"""
from __future__ import annotations

import json
import re
import traceback
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from boxmunge.api.audit import AuditError, AuditLog, audit_record, redact
from boxmunge.api.context import ActionContext, HostProbe
from boxmunge.api.job_capture import (
    CaptureResult, CoreFailed, OutputTail, capture_output, failure_message,
)
from boxmunge.api.job_events import EventLog
from boxmunge.api.job_gate import GateTimeout, job_gate
from boxmunge.api.job_recovery import advice_text, retry_command
from boxmunge.api.job_writer import claim, finish
from boxmunge.api.param_tiers import param_tier_refusal
from boxmunge.api.principal import Principal, Tier, refusal
from boxmunge.api.registry import Action, Registry
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.api.schema import validate
from boxmunge.api.worker_identity import PROC, current
from boxmunge.fileutil import LockError, LockWaitTimeout, project_lock_wait
from boxmunge.fleet import PROJECT_INPUT_ERRORS
from boxmunge.log import log_error, log_operation, log_warning
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError
from boxmunge.termination import Terminated

JOB_LOCK_WAIT_SECONDS = 120
EX_TEMPFAIL = 75
NO_RUNNABLE_JOB = 1
COMPONENT = "jobs"
CUT_OFF = ("Output was cut off: a process this job started still held its output open "
           "after the job's work ended, so anything it printed later is not shown.")
_AGENT_ID = re.compile(r"agent:mcp\((.+)\)")


def run_job(paths: BoxPaths, job_id: str, registry: Registry, host: HostProbe, *,
            proc: Path = PROC) -> int:
    """Run queued job *job_id* to a terminal state: 0. EX_TEMPFAIL when an
    upgrade held the jobs gate (the job stays queued); NO_RUNNABLE_JOB when
    the job is not queued."""
    try:
        with job_gate(paths) as waited:
            if waited:
                log_operation(COMPONENT, f"job {job_id}: an upgrade held the jobs gate, so "
                              f"the job is left queued to run on the code it installed", paths)
                return EX_TEMPFAIL
            record = claim(paths, job_id, current(proc), _now())
            if record is None:
                log_warning(COMPONENT, f"job {job_id} is not queued: another worker has it, "
                            f"or it has finished or never existed", paths)
                return NO_RUNNABLE_JOB
            _Worker(paths, record, registry, host).run()
    except GateTimeout as e:
        log_warning(COMPONENT, f"job {job_id}: {e} The job is left queued.", paths)
        return EX_TEMPFAIL
    return 0


@dataclass
class _Outcome:
    state: str
    error: dict[str, str] | None = None
    result: dict[str, Any] | None = None
    # A core that exited non-zero: its message is built once the capture
    # has drained, so the last lines of its output are in the tail.
    core_failed: CoreFailed | None = None


def _failed(code: ErrorCode, message: str) -> _Outcome:
    return _Outcome("failed", {"code": code.value, "message": message})


@dataclass
class _Prepared:
    action: Action
    params: dict[str, Any]
    principal: Principal
    after: list[Callable[[], None]] = field(default_factory=list)
    tail: OutputTail = field(default_factory=OutputTail)
    # Set once the handler is called, and once it has returned or raised:
    # what a SIGTERM says depends on how far the job got.
    started: bool = False
    returned: _Outcome | None = None


class _Worker:
    def __init__(self, paths: BoxPaths, record: dict[str, Any], registry: Registry,
                 host: HostProbe) -> None:
        self._paths = paths
        self._record = record
        self._registry = registry
        self._host = host
        self._id: str = record["id"]
        self._name: str = record["action"]
        self._project: str | None = record["project"]
        self._audited_params: dict[str, Any] | None = None

    def run(self) -> None:
        events = self._open_events()
        if isinstance(events, _Outcome):
            self._conclude(events, None)
            return
        stopped: Terminated | None = None
        prepared: _Prepared | _Outcome | None = None
        try:
            prepared = self._prepare()
            outcome = prepared if isinstance(prepared, _Outcome) else self._execute(
                prepared, events)
        except Terminated as e:
            job = prepared if isinstance(prepared, _Prepared) else None
            stopped, (outcome, alert) = e, self._stopped(job, events)
        self._conclude(outcome, events)
        if stopped is not None:
            if alert is not None:
                notify(self._paths, f"boxmunge: job {self._id} ({self._name} "
                       f"{self._project}) was stopped", alert, component=COMPONENT,
                       project=self._project, priority=1)
            raise stopped

    def _open_events(self) -> EventLog | _Outcome:
        """The job's event log with `running` written, or the failure that
        says why it cannot be written (nothing has run). A torn last line
        (a crash mid-write) is a StateError naming the file."""
        try:
            events = EventLog(self._paths, self._id)
        except (StateError, OSError) as e:
            return self._unloggable(e)
        try:
            events.state("running")
        except OSError as e:
            events.close()
            return self._unloggable(e)
        return events

    def _unloggable(self, error: Exception) -> _Outcome:
        path = self._paths.jobs_dir / f"{self._id}.events.jsonl"
        return _failed(ErrorCode.FAILED,
                       f"The job's event log {path} cannot be written: {error}. Nothing was "
                       f"run. Run the same call again ({self._retry_command()}); a new job "
                       f"gets a new log. Move {path} aside to keep it for inspection.")

    def _prepare(self) -> _Prepared | _Outcome:
        """The action, parameters and principal, checked on the code
        installed now; or the failure that stops the job before it runs."""
        try:
            action = self._registry.get(self._name)
        except ActionError:
            return _failed(ErrorCode.NOT_FOUND,
                           f"{self._name} is no longer an action of this boxmunge (boxmunge "
                           f"changed between publish and run), so nothing was run.")
        try:
            params = json.loads(self._record["params"])
        except ValueError as e:
            return _failed(ErrorCode.FAILED, f"The job record's params are not JSON ({e}), "
                           f"so nothing was run. Run the call again.")
        violations = validate(action.params, params)
        problem = None if violations or not action.param_check else action.param_check(params)
        if violations or problem:
            why = "; ".join(violations) or problem
            return _failed(ErrorCode.INVALID_PARAMS,
                           f"the job's parameters no longer match {self._name} (boxmunge "
                           f"changed between publish and run): {why}. Nothing was run; "
                           f"run the call again.")
        self._audited_params = redact(action.params, params)
        unknown = sorted(set(action.locks) - {"project"})
        if unknown:
            return _failed(ErrorCode.FAILED, f"internal error: {self._name} needs lock(s) "
                           f"{', '.join(unknown)}, which the job worker cannot take. Nothing "
                           f"was run. This is a boxmunge bug; please report it.")
        try:
            principal = _principal(self._record["principal"])
        except StateError as e:
            return _failed(ErrorCode.FAILED, f"{e} Nothing was run.")
        why = refusal(principal, action.tier, agent_allowed=action.agent_allowed) or \
            param_tier_refusal(action, params, principal, frozenset(Tier))
        if why is not None:
            return _failed(ErrorCode.FORBIDDEN,
                           f"{principal.id} may no longer make this {self._name} call "
                           f"(boxmunge changed between publish and run): {why} Nothing "
                           f"was run.")
        return _Prepared(action, params, principal)

    def _execute(self, job: _Prepared, events: EventLog) -> _Outcome:
        def on_line(line: str) -> None:
            job.tail.append(line)
            events.log(line)

        ctx = ActionContext(principal=job.principal, paths=self._paths, host=self._host,
                            result_schemas=self._result_schema_of,
                            emit=lambda event: _emit(events, event),
                            after_release=job.after.append)
        outcome: _Outcome | None = None
        captured: CaptureResult | None = None
        try:
            with capture_output(on_line) as captured:
                try:
                    outcome = self._call(job, ctx, events)
                finally:
                    self._after_release(job.after, events)
        except Exception as e:  # noqa: BLE001 - outside the handler; the job must finish
            log_error(COMPONENT, f"job {self._id} ({self._name}): {type(e).__name__}: {e}",
                      self._paths, project=self._project,
                      detail={"traceback": traceback.format_exc()})
            if outcome is None:
                ran = "" if job.started else " Nothing was run."
                outcome = _failed(ErrorCode.FAILED,
                                  f"internal error: {type(e).__name__}: {e}.{ran}")
        outcome = self._core_failure(job, outcome)
        if captured is not None and captured.cut_off:
            self._log(events, CUT_OFF)
            if outcome.error is not None:
                outcome.error["message"] += f" {CUT_OFF}"
        return self._checked(job.action, outcome)

    def _core_failure(self, job: _Prepared, outcome: _Outcome) -> _Outcome:
        """*outcome*, with a failed core's message built from the output
        tail (call it once the capture has drained)."""
        failed = outcome.core_failed
        if failed is None:
            return outcome
        return _failed(ErrorCode.FAILED, failure_message(failed.verb, failed.rc, job.tail,
                                                         job_id=self._id))

    def _call(self, job: _Prepared, ctx: ActionContext, events: EventLog) -> _Outcome:
        """Take the locks, run the handler, release the locks."""
        with ExitStack() as locks:
            project = job.params.get("project")
            try:
                for _lock in job.action.locks:  # only "project" (_prepare checked)
                    locks.enter_context(self._project_lock(project, events))
            except LockWaitTimeout as e:
                self._step(events, "lock", "failed", f"{e.project}'s lock stayed held")
                return self._busy(e)
            except (LockError, OSError) as e:
                self._step(events, "lock", "failed", f"{type(e).__name__}: {e}")
                return _failed(ErrorCode.FAILED,
                               f"{project}'s lock could not be taken: {type(e).__name__}: "
                               f"{e}. Nothing was run. Run the same call again: "
                               f"{self._retry_command()}")
            job.started = True
            job.returned = self._handle(job, ctx)
            return job.returned

    def _handle(self, job: _Prepared, ctx: ActionContext) -> _Outcome:
        """Run the handler; its outcome, whatever it raised (but Terminated)."""
        try:
            return _Outcome("succeeded", result=job.action.handler(job.params, ctx))
        except CoreFailed as e:
            return _Outcome("failed", core_failed=e)
        except ActionError as e:
            return _Outcome("failed", {"code": e.code.value, "message": e.message})
        except PROJECT_INPUT_ERRORS as e:
            return _failed(ErrorCode.FAILED, str(e))
        except Exception as e:  # noqa: BLE001 - a bug; the job must still finish
            log_error(COMPONENT, f"job {self._id} ({self._name}) raised "
                      f"{type(e).__name__}: {e}", self._paths, project=self._project,
                      detail={"traceback": traceback.format_exc()})
            return _failed(ErrorCode.FAILED, f"internal error: {type(e).__name__}: {e}")

    @contextmanager
    def _project_lock(self, project: str, events: EventLog) -> Iterator[None]:
        waited: list[bool] = []

        def on_wait(holder: str | None) -> None:
            waited.append(True)
            self._step(events, "lock", "started", f"waiting for {project}'s lock, held by "
                       f"{holder or 'an unknown process'}")

        with project_lock_wait(project, self._paths, timeout=JOB_LOCK_WAIT_SECONDS,
                               on_wait=on_wait):
            if waited:
                self._step(events, "lock", "succeeded", f"took {project}'s lock")
            yield

    def _busy(self, e: LockWaitTimeout) -> _Outcome:
        return _failed(ErrorCode.BUSY,
                       f"{e.project}'s lock was held by {e.holder or 'an unknown process'} "
                       f"for the whole {_duration(JOB_LOCK_WAIT_SECONDS)} this job waited. "
                       f"Nothing was changed. Run the same call again once it is free: "
                       f"{self._retry_command()}")

    def _after_release(self, after: list[Callable[[], None]], events: EventLog) -> None:
        """Run each callable the handler left, now that its locks are free.
        A failure is logged and reported in the events; the job's outcome
        stands, since its work is done."""
        for call in after:
            try:
                call()
            except Exception as e:  # noqa: BLE001 - reported, the others still run
                log_error(COMPONENT, f"job {self._id}: an after-release step failed: "
                          f"{type(e).__name__}: {e}", self._paths, project=self._project,
                          detail={"traceback": traceback.format_exc()})
                self._step(events, "after_release", "failed", f"{type(e).__name__}: {e}")

    def _checked(self, action: Action, outcome: _Outcome) -> _Outcome:
        if outcome.state != "succeeded":
            return outcome
        violations = validate(action.result, outcome.result,
                              result_schemas=self._result_schema_of)
        if not violations:
            return outcome
        log_error(COMPONENT, f"{self._name} returned a result outside its schema (job "
                  f"{self._id})", self._paths, detail={"violations": violations})
        return _failed(ErrorCode.FAILED,
                       f"{self._name} returned a result that does not match its schema. "
                       f"This is a boxmunge bug; please report it. Its work may be done: "
                       f"check with boxmunge status {self._project}.")

    def _stopped(self, job: _Prepared | None,
                 events: EventLog) -> tuple[_Outcome, str | None]:
        """The outcome of a job a SIGTERM stopped, and the alert to send
        (None when nothing was changed)."""
        if job is None or not job.started:
            return _failed(ErrorCode.FAILED,
                           f"stopped by SIGTERM (a service stop or shutdown) before it "
                           f"started. Nothing was changed; run the same call again: "
                           f"{self._retry_command()}"), None
        if job.returned is not None:
            note = ("stopped by SIGTERM (a service stop or shutdown) after its work "
                    "finished, while its after-release steps ran; some of them may not "
                    "have run.")
            self._log(events, note)
            outcome = self._checked(job.action, self._core_failure(job, job.returned))
            if outcome.error is not None:
                outcome.error["message"] += f" It was {note}"
            return outcome, f"Job {self._id} ({self._name}) {outcome.state}, and was {note}"
        advice = advice_text(self._paths, self._name, self._project)
        message = (f"stopped by SIGTERM (a service stop or shutdown); it was not run "
                   f"again, and may have done part of its work. To recover: {advice}.")
        return _failed(ErrorCode.FAILED, message), message

    def _conclude(self, outcome: _Outcome, events: EventLog | None) -> None:
        try:
            finish(self._paths, self._id, state=outcome.state, error=outcome.error,
                   result=outcome.result, now=_now(), result_schemas=self._result_schema_of)
            if events is not None:
                try:
                    events.state(outcome.state)
                except OSError as e:
                    log_error(COMPONENT, f"job {self._id}: could not write its {outcome.state} "
                              f"event: {e}", self._paths, project=self._project)
            self._audit(outcome)
        finally:
            if events is not None:
                events.close()

    def _audit(self, outcome: _Outcome) -> None:
        error = outcome.error or {}
        principal = self._record["principal"]
        record = audit_record(principal, self._name, outcome.state,
                              params=self._audited_params, code=error.get("code"),
                              message=error.get("message"), job=self._id)
        try:
            AuditLog(self._paths.audit_log, create=False).append(record)
        except AuditError as e:
            log_error("audit", f"could not record the outcome of {self._name} (job "
                      f"{self._id}): {e}", self._paths,
                      detail={"outcome": outcome.state, "principal": principal})
            notify(self._paths, "boxmunge: audit log write failed",
                   f"The outcome ({outcome.state}) of {self._name} by {principal} (job "
                   f"{self._id}) was not recorded: {e}. The job record keeps it.",
                   component="audit", priority=1)

    def _step(self, events: EventLog, step: str, status: str, message: str) -> None:
        """A step event the worker writes; a write failure is logged, never
        allowed to change the job's outcome."""
        try:
            events.step(step, status, message)
        except OSError as e:
            log_error(COMPONENT, f"job {self._id}: could not write step {step} {status}: "
                      f"{e}", self._paths, project=self._project)

    def _log(self, events: EventLog, message: str) -> None:
        try:
            events.log(message)
        except OSError as e:
            log_error(COMPONENT, f"job {self._id}: could not log {message!r}: {e}",
                      self._paths, project=self._project)

    def _retry_command(self) -> str:
        return retry_command(self._record)

    def _result_schema_of(self, name: str) -> dict[str, Any] | None:
        try:
            return self._registry.get(name).result
        except ActionError:
            return None


def _emit(events: EventLog, event: dict[str, Any]) -> None:
    """ctx.emit: a handler's step, {"step", "status"[, "message"]}."""
    unknown = set(event) - {"step", "status", "message"}
    if unknown or not {"step", "status"} <= set(event):
        raise ValueError(f"ctx.emit takes step, status and an optional message, not "
                         f"{sorted(event)}")
    events.step(event["step"], event["status"], event.get("message"))


def _principal(principal_id: str) -> Principal:
    """The principal a job was published by. Only operators and agents can
    publish operate jobs in this release, and their ids name them fully; a
    grant is not recorded, so no other principal can be rebuilt."""
    kind, _, name = principal_id.partition(":")
    agent = _AGENT_ID.fullmatch(principal_id)
    try:
        if kind == "operator":
            return Principal.operator(name)
        if agent is not None:
            return Principal.agent(agent[1])
    except ValueError as e:
        raise StateError(f"The job's principal {principal_id} is not valid: {e}.") from e
    raise StateError(f"The job was published by {principal_id}, and this worker runs only "
                     f"jobs published by an operator or an agent.")


def _duration(seconds: float) -> str:
    if seconds >= 60 and seconds % 60 == 0:
        minutes = int(seconds // 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    return f"{seconds:g} seconds"


def _now() -> datetime:
    return datetime.now(timezone.utc)
