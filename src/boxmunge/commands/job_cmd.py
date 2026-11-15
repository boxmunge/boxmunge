# SPDX-License-Identifier: Apache-2.0
"""The operator's job commands.

  job run <action> [<params-json>] [--detach]   queue a job action, then follow it
  job show <id> [--events] [--json]             one job's record (and its events)
  jobs [--project P] [--running] [--json]       recent jobs, newest first

`job run` goes through the action API's Invoker, so the call is checked and
audited like any other; the job runner (boxmunge-jobs.path) starts the worker.
Following polls the job's record and events every FOLLOW_POLL_SECONDS; Ctrl-C
stops following, never the job.
"""
from __future__ import annotations

import json
import re
import sys
import time
from typing import TYPE_CHECKING, Any, NoReturn

from boxmunge.commands.argv import parse_args, usage_error
from boxmunge.fs_nofollow import running_as_root
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

if TYPE_CHECKING:
    from boxmunge.api.jobs import JobStore
    from boxmunge.api.registry import Registry
    from boxmunge.api.result import ActionError

FOLLOW_POLL_SECONDS = 1
QUEUED_HINT_SECONDS = 30
QUEUED_HINT = (f"still queued after {QUEUED_HINT_SECONDS} s: is the job runner active? "
               f"systemctl status boxmunge-jobs.path")
EXIT_INTERRUPTED = 130
UNFINISHED = frozenset({"queued", "running"})
# Patched by tests, which run the worker inline in place of the runner.
_sleep = time.sleep
_monotonic = time.monotonic


def cmd_job(args: list[str]) -> None:
    if not args:
        usage_error("job", "job needs a subcommand: run or show")
    sub, rest = args[0], args[1:]
    if sub == "run":
        _job_run(rest)
    elif sub == "show":
        _job_show(rest)
    else:
        usage_error("job", f"unknown job subcommand {sub!r}: use run or show")


def cmd_jobs(args: list[str]) -> None:
    from boxmunge.api.actions.jobs import JOBS_LIMIT_DEFAULT
    parsed = parse_args("jobs", args, flags={"--running", "--json"}, options={"--project"})
    running = parsed.has("--running")
    listing = _store(BoxPaths()).recent(project=parsed.get("--project"),
                                        limit=None if running else JOBS_LIMIT_DEFAULT)
    jobs = [j for j in listing.jobs if j["state"] in UNFINISHED] if running else listing.jobs
    if parsed.has("--json"):
        print(json.dumps({"jobs": jobs, "unreadable": listing.unreadable}, indent=2))
    elif jobs:
        print(f"{'ID':<26}  {'STATE':<9}  {'ACTION':<24}  {'PROJECT':<20}  CREATED")
        for job in jobs:
            error = f"  ({job['error']['code']})" if job["error"] else ""
            print(f"{job['id']:<26}  {job['state']:<9}  {job['action']:<24}  "
                  f"{job['project'] or '-':<20}  {job['created_at']}{error}")
    else:
        print("No queued or running jobs." if running else "No jobs.")
    for bad in listing.unreadable:
        print(f"WARNING: job {bad['id']} cannot be read: {bad['problem']}", file=sys.stderr)
    if listing.unreadable:
        sys.exit(1)


def _job_run(args: list[str]) -> None:
    from boxmunge.api.actions import build_registry
    from boxmunge.api.audit import AuditLog
    from boxmunge.api.host import LiveHost
    from boxmunge.api.invoke import Invoker
    from boxmunge.api.principal import Principal
    from boxmunge.api.result import ActionError
    parsed = parse_args("job", args, flags={"--detach"}, min_positional=1, max_positional=2)
    name = parsed.positional[0]
    params = _params(parsed.positional[1] if len(parsed.positional) > 1 else "{}")
    registry = build_registry()
    _require_job_action(registry, name)
    paths = BoxPaths()
    invoker = Invoker(registry, paths, LiveHost(paths),
                      AuditLog(paths.audit_log, create=False), jobs=True)
    principal = Principal.operator("supervisor" if running_as_root() else "ssh")
    try:
        result = invoker.invoke(name, params, principal)
    except ActionError as e:
        _refused(e)
    if not result.job:
        raise AssertionError(f"{name} ran inline although its action is a job")
    job_id = result.data["id"]
    print(f"job {job_id} queued", flush=True)
    if parsed.has("--detach"):
        print(f"follow it with: boxmunge job show {job_id} --events")
        return
    try:
        sys.exit(_follow(_store(paths, registry), job_id))
    except StateError as e:
        _fail(f"{e}. The job itself is not affected; see it with: boxmunge job show {job_id}")


def _job_show(args: list[str]) -> None:
    from boxmunge.api.jobs import JOB_ID_PATTERN
    parsed = parse_args("job", args, flags={"--events", "--json"},
                        min_positional=1, max_positional=1)
    job_id = parsed.positional[0]
    if not re.fullmatch(JOB_ID_PATTERN, job_id):
        usage_error("job", f"{job_id!r} is not a job id (26 characters, a ULID)")
    store = _store(BoxPaths())
    try:
        record = store.get(job_id)
        if record is None:
            _fail(f"no job {job_id}. List recent jobs with: boxmunge jobs")
        events = store.events(job_id) if parsed.has("--events") else None
    except StateError as e:
        _fail(str(e))
    if parsed.has("--json"):
        shown: Any = record if events is None else {"job": record, "events": events}
        print(json.dumps(shown, indent=2))
        return
    print(f"job {record['id']}  {record['action']}  {record['state']}")
    for label, key in (("project", "project"), ("principal", "principal"),
                       ("params", "params"), ("created", "created_at"),
                       ("started", "started_at"), ("finished", "finished_at")):
        print(f"  {label + ':':<11}{record[key] if record[key] is not None else '-'}")
    if record["error"]:
        print(f"  {'error:':<11}{record['error']['code']}: {record['error']['message']}")
    if record["result"] is not None:
        print(f"  {'result:':<11}{json.dumps(record['result'])}")
    if events is not None:
        print("events:")
        for event in events:
            line = _event_line(event)
            if line is not None:
                print(f"  {event['ts']}  {line}")


def _follow(store: JobStore, job_id: str) -> int:
    """Print the job's events as they come until it is terminal; its exit code."""
    seq, hinted, began = 0, False, _monotonic()
    try:
        while True:
            # The record is read before the events: a worker writes every
            # log event before it finishes the record, so none is missed.
            record = store.get(job_id)
            if record is None:
                _fail(f"job {job_id} disappeared while it was followed. This is a "
                      f"boxmunge bug; please report it.")
            for event in store.events(job_id, after=seq):
                seq = event["seq"]
                line = _event_line(event)
                if line is not None:
                    print(line, flush=True)
            if record["state"] not in UNFINISHED:
                return _concluded(record)
            if (record["state"] == "queued" and not hinted
                    and _monotonic() - began >= QUEUED_HINT_SECONDS):
                print(QUEUED_HINT, file=sys.stderr, flush=True)
                hinted = True
            _sleep(FOLLOW_POLL_SECONDS)
    except KeyboardInterrupt:
        print(f"\nthe job keeps running; follow it with: boxmunge job show {job_id} --events",
              file=sys.stderr)
        return EXIT_INTERRUPTED


def _concluded(record: dict[str, Any]) -> int:
    if record["state"] == "succeeded":
        print(f"job {record['id']} succeeded")
        if record["result"] is not None:
            print(f"result: {json.dumps(record['result'])}")
        return 0
    error = record["error"]
    print(f"ERROR: {error['code']}: {error['message']}", file=sys.stderr)
    return 1


def _event_line(event: dict[str, Any]) -> str | None:
    """How an event reads to the operator; None for terminal state events,
    which the follower reports from the record."""
    if event["type"] == "log":
        return event["message"]
    if event["type"] == "step":
        text = f"[{event['step']}] {event['status']}"
        return f"{text}: {event['message']}" if "message" in event else text
    if event["state"] in UNFINISHED:
        return f"-- {event['state']}"
    return None


def _params(text: str) -> dict[str, Any]:
    try:
        params = json.loads(text)
    except ValueError as e:
        usage_error("job", f"the params are not JSON ({e}); give one JSON object, "
                           f"e.g. '{{\"project\":\"myapp\"}}'")
    if not isinstance(params, dict):
        usage_error("job", "the params must be a JSON object, e.g. '{\"project\":\"myapp\"}'")
    return params


def _require_job_action(registry: Registry, name: str) -> None:
    jobs = ", ".join(a.name for a in registry.actions() if a.job)
    known = {a.name: a for a in registry.actions()}
    if name not in known:
        usage_error("job", f"unknown action {name!r}. Job actions: {jobs}")
    if not known[name].job:
        usage_error("job", f"{name} does not run as a job. Job actions: {jobs}")


def _store(paths: BoxPaths, registry: Registry | None = None) -> JobStore:
    """The job reader; it checks a job's result against *registry* (the
    full one by default)."""
    from boxmunge.api.actions import build_registry
    from boxmunge.api.jobs import JobStore
    actions = (build_registry() if registry is None else registry).actions()
    results = {a.name: a.result for a in actions}
    return JobStore(paths, result_schemas=results.get)


def _refused(error: ActionError) -> NoReturn:
    print(f"ERROR: {error.message}", file=sys.stderr)
    for violation in (error.details or {}).get("violations", []):
        print(f"  - {violation}", file=sys.stderr)
    sys.exit(1)


def _fail(message: str) -> NoReturn:
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)
