# boxmunge plugin API

This is the contract between boxmunge and its plugins: a web UI, an assistant, or any service that
runs on a box and reads or drives the platform. It covers what this release serves and, marked as
**planned**, the parts that arrive in later releases, so you can design for them now.

API version: **1.0**.

### Versioning and what your client must tolerate

`api_version` is `1.<minor>`, carried by every response, the catalog included. The minor number goes
up with any addition: new actions, new optional parameters, new result fields, new enum values, new
`details` keys, new error codes, new endpoints. The major number changes only for a breaking change,
and nothing you rely on is renamed or removed within `1.x`. So that additions never break you,
clients:

- MUST ignore result fields they do not know;
- MUST treat an enum value they do not know as "other" (for example, an unfamiliar `lifecycle`);
- MUST ignore `details` keys they do not know;
- MUST treat an error code they do not know as `failed`.

## Concepts

**Action.** A named platform operation such as `status.get` or `project.get`. Every action has a
parameter schema, a result schema and a tier. Names are `<noun>.<verb>`.

**Tier.** How much an action can change.

| Tier | Meaning |
|---|---|
| `observe` | Reads state; changes nothing |
| `operate` | Runs or changes a project within its declared configuration (planned for plugins) |
| `govern` | Changes policy or secrets. Never available to plugins |
| `platform` | Changes the platform itself. Never available to plugins |

**Principal.** Who is calling. A plugin's principal is `plugin:<name>`, fixed by the socket it
connects through. Nothing you send can change it.

**Grant.** The highest tier your plugin may use, set when the operator installs it: `observe` or
`operate`. The catalog lists only what your grant allows.

## Transport

HTTP/1.1 with JSON bodies over a unix socket. On a box the socket is
`/run/boxmunge/plugins/<plugin>/api.sock` (planned). In dev mode it is wherever you say.

- Requests with a body must send `Content-Length`; chunked bodies are refused. The limit is 64 KiB.
- Responses are always `application/json` and always carry `api_version`.
- Keep-alive works; the server closes the connection after any malformed request.
- The server serves at most 16 connections at once. One more gets `503 unavailable` and is
  closed.
- A request (headers and body) must arrive whole within 30 seconds of the server starting to
  read it, or the connection is closed. A kept-alive connection that sits idle for that long is
  closed too, so a pooled socket can be gone when you next use it.

Clients should keep a small connection pool (a handful of sockets, not one per request), and
retry on `503` or on a connection reset or close, with a short backoff. Every observe action is
safe to retry.

Any language works. With curl: `curl --unix-socket ./api.sock http://boxmunge/v1/actions`. In
Node, pass `socketPath` to `http.request`.

### Response envelope

Success:

```json
{"api_version": "1.0", "ok": true, "action": "status.get", "data": {"projects": []}}
```

Failure:

```json
{"api_version": "1.0", "ok": false,
 "error": {"code": "not_found", "message": "Project not found: shop. ...", "details": {}}}
```

`details` is present only when there is more to say, for example `details.violations` on
`invalid_params`. Messages say what to do next; show them to the operator as they are.

## Endpoints

| Method and path | Served | Purpose |
|---|---|---|
| `GET /v1/actions` | yes | The catalog: every action your grant allows, with schemas |
| `POST /v1/actions/<name>` | yes | Invoke. Body: `{"params": {...}}` |
| `GET /v1/jobs/<id>` | yes | One job record (same as `job.get`) |
| `GET /v1/jobs/<id>/events` | planned | Server-sent events for one job; `Last-Event-ID` resumes |
| `GET /v1/events` | planned | Server-sent state changes for dashboards |
| `POST /v1/approvals` | planned | Request an operator approval for one operate call |

An endpoint that is not served yet answers `404 not_found`. Until the event streams arrive, poll
`job.events` with `after` set to the last `seq` you saw.

### The catalog

`GET /v1/actions` returns:

```json
{"api_version": "1.0", "ok": true,
 "data": {"principal": "plugin:webui", "mode": "dev",
          "actions": [{"name": "project.get", "tier": "observe", "summary": "...",
                       "params": {...}, "result": {...}, "job": false}]}}
```

`mode` is `dev` when the server is serving a fixture box. `job: true` marks an action that runs as
a job (planned: every operate action is a job). Invoking one returns HTTP 202, and
`data` is the job record (`id`, `action`, `state` `"queued"`, timestamps; see "Jobs"). For such an action the
catalog's `result` schema describes the job record's `result` field once the job succeeds.

### Invoking

```text
POST /v1/actions/project.get
{"params": {"project": "shop"}}
```

`params` is required; send `{}` for an action that takes none. The only other field allowed is
`approval` (planned, operate calls only).

## Schemas

Parameter and result schemas use a small JSON Schema subset: `type`, `properties`, `required`,
`additionalProperties`, `enum`, `pattern`, `minimum`, `maximum`, `minLength`, `maxLength`, `items`,
`const`, plus the annotations `description` and `secret`, and one keyword of boxmunge's own:

- `x-result-of-action: true` appears only on a job record's `result` property, beside its `action`
  property. It means the value is null or the result of the action that `action` names, matching
  that action's catalog `result` schema (an unknown action is invalid). Its `type` is
  `["object", "null"]`. A client that does not understand the keyword can
  treat `result` as any JSON value or null.

- Every object schema sets `additionalProperties: false`. Unknown parameters are refused. The
  server checks every result it sends against the schema it publishes, but within `1.x` a
  published result schema may gain optional fields and enum values: read results tolerantly, as
  "Versioning" above says.
- `type` may be a list, such as `["string", "null"]`, for a value that can be null.
- `pattern` must match the **whole** string, as if written `^...$`. Anchor it yourself if you
  reuse it in JavaScript.
- `true` and `false` are never integers: `{"tail": true}` is refused.
- Every timestamp in a result is ISO 8601 in UTC with a trailing `Z`
  (`2026-10-14T02:30:00Z`, with microseconds when the platform recorded them). Calendar dates,
  such as a suppression's `until`, are `YYYY-MM-DD`.
- Enum values are lowercase machine values (`failing`, not `FAILING`); a value that does not
  apply is `null`, never a placeholder such as `-`.
- There is no `default` keyword. Where a parameter is optional, its `description` states the
  default the server applies.

## Error codes

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_params` | 422 | Parameters or the request body fail validation; `details.violations` lists each |
| `not_found` | 404 | Unknown action, endpoint, project, job, or snapshot |
| `forbidden` | 403 | Your grant does not allow this action, or this server does not serve its tier |
| `approval_required` | 401 | An operate call arrived without an approval (planned flow) |
| `approval_invalid` | 401 | The approval sent cannot be used: unknown, expired, already used, or bound to another call |
| `busy` | 409 | The project lock is held by another operation; retry shortly |
| `conflict` | 409 | The project's state forbids it: not yet deployed, quarantined, paused, staged |
| `stale_approval` | 409 | The project changed after the operator approved; request a new approval |
| `governed_change` | 403 | A plugin deploy would change the project's policy; the operator deploys it over SSH |
| `failed` | 500 | The action ran and failed, or box state could not be read; the message says why |
| `unavailable` | 503 | A dependency is down (Docker, the audit log), a job action has no runner yet, or the server has too many connections open; retry shortly |

A request the HTTP layer cannot parse (an over-long header line, say) gets its HTTP status, such
as 400 or 431, with the same JSON envelope and code `invalid_params`.

## Observe actions

The catalog is the authority on parameters and result fields; this table is the overview.

| Action | Parameters | Returns |
|---|---|---|
| `platform.info` | none | `api_version`, `server_version`, `build`, `min_client_version`, `schema_version`, `hostname` |
| `status.get` | none | `projects`: one row per project: `status` (ok, failing, critical_stopped, unknown, quarantined, paused, pre_registered, error), `last_check`, `deployed_at`, `quarantine` (`cve_id`, `severity`, `explanation`, `quarantined_at`) and `error`, null where they do not apply |
| `projects.list` | none | `projects`: registered project names |
| `health.get` | none | `healthy`, `exit_code`, `checks` (`name`, `status` ok/warn/error/skip, `detail`) |
| `project.get` | `project` | `lifecycle` (running, paused, quarantined, monitor_stopped, pre_registered, registered), `health`, `deploy` with history, `staging` (`active`, and the staged release's `id`, `ref` and `state`: starting, ready or retired; null when nothing is staged), `paused`, `quarantine`, `install` (an install that has not finished: `id`, `source` bundle, staged, rollback or git, `ref`, and `phase`; null when none is open), `legacy_stage` (a release staged by boxmunge 0.10.1 that the operator has not resolved: `kind` bundle, git or leftover, and `evidence`, whether production's containers are untouched by the stage or recreated from it: unknown when that cannot be read, null for a leftover; null when there is no such stage) |
| `project.health` | `project` | Runs the smoke checks now: `exit_code`, `status`, `smoke` |
| `project.logs` | `project`, `service`?, `tail`? (1-1000, default 100) | `lines` of container log output |
| `oplog.query` | `project`?, `component`?, `level`?, `since`? (`30m`, `6h`, `7d`), `tail`? (default 50) | `entries` of the operational log; `detail` is compact JSON text or null |
| `security.summary` | none | Fleet CVE view: posture counts, quarantined and at-risk projects, suppressions, breaker holds |
| `security.project` | `project` | `status` (normal, quarantined, at_risk_running), `findings` with dispositions, `quarantine`, `active_suppressions`, `off_services` |
| `backups.list` | `project` | `snapshots`, newest first: `name`, `kind`, `taken_at`, `size` |
| `inbox.list` | `project`? | `bundles` uploaded and not yet deployed |
| `jobs.list` | `project`?, `limit`? (1-200, default 50) | `jobs`, newest first; `unreadable` (`id`, `problem`), present only when some job record cannot be read |
| `job.get` | `id` | One job record |
| `job.events` | `id`, `after`? (default 0) | `events` with `seq` greater than `after` |

`project.health` runs the project's smoke checks inside its containers each time it is called:
it is an observe action, but not free of side effects, so call it when someone asks rather than
polling it. `project.get` and `status.get` report the result of the platform's own periodic checks.

### Jobs

A job is the record of a long-running action. Its record has `id` (a ULID), `action`, `principal`,
`project`, `state` (`queued`, `running`, `succeeded`, `failed`), `created_at`, `started_at`,
`finished_at`, `error` (`{code, message}` or null) and `result` (the action's result once the job
has succeeded, in the shape of that action's catalog `result` schema, as `x-result-of-action`
declares; null until then, and always null in this release). Events have `seq` (from 1), `ts` and `type`:

- `log`: a line of output, in `message`;
- `step`: a named step (`step`) that `started`, `succeeded` or `failed` (`status`), with an optional
  `message`;
- `state`: the job entered `state`.

In this release no job can be started through the API, so jobs come from the fixture in dev mode.

## Operate actions and approvals (planned)

Operate actions (stage, promote, unstage, deploy, rollback, pause, resume, backup, restore) will
be served to plugins granted `operate`, and each call will need the operator's fresh approval:

1. `POST /v1/approvals` with `{"action": "project.rollback", "params": {"project": "shop"}}`.
   The server resolves the call into a plan (the exact release and snapshot) and returns
   `{"approval_id", "approve_url"}`.
2. Send the operator's browser to `approve_url`. The platform's own page shows the plan, and the
   operator confirms with a passkey. Your plugin never sees the credential.
3. `POST /v1/actions/project.rollback` with `{"params": {...}, "approval": {"approval_id": "..."}}`.
   You get a job back. Retrying the same call with the same approval returns the same job.

An approval is good for one call, for two minutes, and only for exactly the parameters and plan the
operator saw. If the project changes before the job runs, the job fails with `stale_approval`. A
deploy that would change the project's policy is `governed_change`.

Until then, an operate call from a plugin is refused, and the catalog does not list operate
actions.

## Dev mode: build without a server

You need Python 3.10 or newer and a clone of this repository.

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.txt
.venv/bin/pip install --no-deps -e .

.venv/bin/boxmunge-apid --make-fixture ~/bm-fixture
.venv/bin/boxmunge-apid --dev --root ~/bm-fixture --socket ./api.sock --plugin webui
```

The fixture is a realistic box: `shop` running with a deploy history and findings, `blog` paused,
`billing` quarantined for a critical CVE, `wiki` failing its smoke check with a staged release,
`newapp` registered but never deployed, plus backups, inbox bundles, an operational log, a health
report and finished jobs with events. Timestamps are relative to when you made it; make a new one
for fresh data.

Dev mode serves only directories made by `--make-fixture`, only observe actions, and only as
`plugin:<name>` with an observe grant. It writes the audit log into the fixture
(`logs/audit.jsonl`), where refused calls show up.

### Walkthrough

```sh
S=./api.sock
curl -s --unix-socket $S http://boxmunge/v1/actions | python3 -m json.tool | head -40
curl -s --unix-socket $S -d '{"params": {}}' http://boxmunge/v1/actions/status.get
curl -s --unix-socket $S -d '{"params": {"project": "billing"}}' \
     http://boxmunge/v1/actions/project.get
curl -s --unix-socket $S -d '{"params": {"project": "shop", "service": "web", "tail": 5}}' \
     http://boxmunge/v1/actions/project.logs
curl -s --unix-socket $S -d '{"params": {"level": "error"}}' \
     http://boxmunge/v1/actions/oplog.query
JOB=$(curl -s --unix-socket $S -d '{"params": {"limit": 1}}' \
      http://boxmunge/v1/actions/jobs.list | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["jobs"][0]["id"])')
curl -s --unix-socket $S -d "{\"params\": {\"id\": \"$JOB\", \"after\": 3}}" \
     http://boxmunge/v1/actions/job.events
curl -s --unix-socket $S -d '{"params": {"project": "shop\n"}}' \
     http://boxmunge/v1/actions/project.get     # 422 invalid_params
```

`curl -d` sends a POST with `Content-Length`, which is all the server needs.
