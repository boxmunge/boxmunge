# boxmunge CVE Policy

How boxmunge handles CVEs published against deployed images: daily scanning,
posture-based quarantine, suppression workflow, and recovery.

## TL;DR for agents

- **Daily scan via Trivy.** Every project's deployed images are scanned at
  03:00 system time (±30 min jitter); also on every deploy and image update.
- **Posture per project (default `balanced`).** `relaxed` quarantines Critical
  only, `balanced` quarantines High and above, `strict` quarantines Medium
  and above. Set in the manifest under `security.posture`.
- **Auto-quarantine** when an unfixed CVE crosses the project's posture
  threshold: `compose stop` + maintenance page + critical Pushover alert.
- **Suppress with operator review:**
  `boxmunge security suppress <CVE> --project <name> --until <YYYY-MM-DD> --reason <text>`.
- **Inspect state:** `boxmunge security` (fleet) or `boxmunge security <project>`
  (per-project). Both accept `--json`.
- **Recover with `boxmunge security resume <project>`** after a fix lands or
  you've added a suppression.

## The promise

Sleep easy: if a published CVE on a deployed image is bad enough by your
declared posture, boxmunge stops the project and serves a maintenance page
before you've had your morning coffee. If it's not bad enough to quarantine,
you still get an informational alert. Either way, you find out.

The constraint that shaped this design: there is no AI agent on the
deployed box doing bespoke "is this exploitable in our context"
reasoning. The policy is rule-based and deterministic. Operators encode
context once, in the manifest (posture) and in suppressions (per-CVE
review notes); the engine reapplies those rules on every scan.

## Decision matrix

For each finding from the scanner against a deployed image:

| Condition | Action |
|---|---|
| CVE has upstream fix available | Auto-update path picks it up; no quarantine. |
| No fix; effective severity below posture threshold | Keep running; informational alert. |
| No fix; effective severity at or above posture threshold | Quarantine (compose stop + maintenance page); critical alert. |
| `dangerously_disable_quarantine: true` | Never quarantine; `[STILL RUNNING]` alert. |
| Active suppression matches the CVE | Skip; revisit on suppression expiry. |
| Severity reported as Unknown by scanner | Informational only — the engine never quarantines on a severity it can't rank. |

## Posture tiers

Per-project, set in `manifest.yml` under `security.posture`. Default `balanced`.

| Tier | Quarantines at effective severity |
|---|---|
| `relaxed` | Critical only |
| `balanced` (default) | High and above |
| `strict` | Medium and above |

`Low` and below never quarantine on their own. They can only become
quarantine-eligible by being elevated into a higher band via the
hardening penalty (see next section).

## Effective severity = base + hardening penalty

The scanner reports a base severity (Low / Medium / High / Critical). If
the project has weakened the boxmunge hardened defaults, that base is
elevated by a hardening penalty before being compared against the
posture threshold.

| Hardening weakened | Penalty |
|---|---|
| `read_only: false` (writeable rootfs) | +1 |
| `no-new-privileges` removed or set to false | +1 |
| `cap_add` beyond image defaults (any non-empty list) | +1 |
| `privileged: true` | +2 (already rejected by validator) |

Penalty is capped at +2 total. The audit ledger and per-finding
explanation show the elevation reason explicitly so you can see why a
Medium CVE quarantined a project running on `strict` posture.

Rationale: running with read-only rootfs disabled means a Medium CVE
behaves more like a High one in practice — the policy treats it that way.

## Configuring posture (manifest.yml)

`posture` and `dangerously_disable_quarantine` live at the project level
only — they are not per-service settings.

```yaml
security:
  posture: balanced                       # default if absent
  dangerously_disable_quarantine: false   # default if absent
```

The compose validator rejects:

- `dangerously_disable_quarantine: true` on a project where any service
  does not set `read_only: true`. Rationale: if you've told us not to
  react to compromise, the read-only rootfs is the last line of defense
  against post-exploit persistence. The trade is uptime over reaction;
  the read-only rootfs is the price.
- `posture: strict` on a project where any service does not set
  `read_only: true`. Strict posture without read-only rootfs is incoherent.
- Any `posture` value other than `relaxed`, `balanced`, or `strict`.

For background on hardening profiles (`profile: default`, `profile: off`),
see [SECURITY.md](SECURITY.md).

## dangerously-disable-quarantine

Use this when uptime is the dominant concern and the service has nothing
to lose. The motivating example: a public weather aggregator with no
secrets, no user data, no auth. You'd rather be exploited than offline.

The trade is explicit and signed off in the manifest:

- You accept that a Critical CVE on this project will not stop the
  service.
- In exchange, you must run with `read_only: true` on every service —
  any post-exploit persistence has nowhere to land.
- Pushover alerts for findings on this project are prefixed
  `[STILL RUNNING — quarantine disabled by config]`.
- The fleet `--json` view always shows the project under
  `at_risk_running` while it has at-or-above-threshold findings.

Example manifest:

```yaml
name: weather-app
hosts:
  - weather.example.com

security:
  posture: balanced
  dangerously_disable_quarantine: true

services:
  web:
    security:
      read_only: true
```

The validator rejects this combination if any service is missing
`read_only: true`.

## Suppressions

A suppression is an operator's signed-off declaration that a CVE has
been reviewed and judged not exploitable in the deployed config. It
skips the policy gate for that one CVE until its `until` date.

The file lives in the project's deploy bundle so the disposition trail
travels with the project (audit history, not platform state):

```
<project>/security/suppressions.yml
```

Schema:

```yaml
suppressions:
  - cve: CVE-2026-1234
    until: 2026-08-01
    reason: "Endpoint not exposed in our config; vulnerable code path unreachable."
    reviewed_by: jon
    added: 2026-05-06
```

All five fields are required. Dates are ISO `YYYY-MM-DD`.

CLI:

```
boxmunge security suppress <CVE> --project <name> --until <YYYY-MM-DD> --reason <text>
boxmunge security unsuppress <CVE> --project <name>
```

The `suppress` command writes the entry, sets `reviewed_by` from `$USER`,
and sets `added` to today. `--until` must be a future date.

Rules:

- Expired suppressions revert automatically. There is no grace, no override:
  on the next scan after `until`, the finding is active again and an alert
  fires.
- Suppression IDs are unique per project. To replace an existing
  suppression, `unsuppress` first, then `suppress` with the new fields.
  This is deliberate — silent overwrites would erase audit-trail entries.
- A suppression is active while `today < until`. So `until: 2026-08-01`
  applies through 2026-07-31 and expires on 2026-08-01.

## Scan cadence

- **Daily** at 03:00 system time via systemd timer `boxmunge-cve-scan.timer`,
  with up to 30 minutes of randomized jitter.
- **On every deploy** and **on every image update**. If a new image would
  immediately quarantine under current posture, the deploy is rejected with
  an error pointing to suppress/posture options.
- **Ad-hoc:**

  ```
  boxmunge security scan              # all projects
  boxmunge security scan <project>    # one project
  ```

The Trivy DB refreshes before each scan. DB-refresh failure is non-fatal:
the existing (possibly stale) DB still scans and a warning is logged.

Idempotency: the daily cron does not re-fire informational alerts for
unchanged dispositions. Only state transitions (new finding, transition
across threshold, suppression expiry, new quarantine, resume) produce
alerts.

## Migration grace

A one-time 24-hour grace window applies after upgrade to v0.6.0 (or after
a fresh install on v0.6.0+). It runs once across the lifetime of the
install — you cannot dodge enforcement by repeatedly upgrading.

- The first scan after upgrade creates a grace marker. For the next 24
  hours, no project gets quarantined.
- A single fleet-level heads-up alert summarizes which projects *would*
  quarantine when grace expires, with pointers to suppress / change
  posture / accept enforcement.
- Per-project transition alerts (new findings, suppression expiry, etc.)
  are silenced during grace — the heads-up is the one alert in this
  window.
- After 24 hours, full enforcement begins on the next scan.

The grace state is visible in `boxmunge security --json` under the
top-level `grace` field.

## Alerts you'll see (Pushover)

Five categories. Titles only — bodies are self-explanatory.

| Title | Priority |
|---|---|
| `[boxmunge:<project>] QUARANTINED — <CVE> (<severity>)` | high |
| `[boxmunge:<project>] [STILL RUNNING — quarantine disabled by config]` | high |
| `[boxmunge:<project>] <CVE> (<severity>)` (informational, sub-threshold) | normal |
| `[boxmunge:<project>] Suppression for <CVE> expired` | high |
| `[boxmunge] CVE policy enforcement begins in <N>h` (one-time) | normal |

Alerting is best-effort. The durable record is the on-disk scan state
under `<project>/.cve/scan_state.json`. If Pushover isn't configured, or
the API call fails, the scan still runs, the quarantine still happens,
and the state file is still written — you just won't get a push.

## CLI reference

```
boxmunge security                                       Fleet summary
boxmunge security --json                                Fleet JSON
boxmunge security <project>                             Per-project view
boxmunge security <project> --json                      Per-project JSON
boxmunge security scan                                  Scan all projects
boxmunge security scan <project>                        Scan one project
boxmunge security suppress <CVE> --project <name> --until <YYYY-MM-DD> --reason <text>
boxmunge security unsuppress <CVE> --project <name>
boxmunge security resume <project>                      Lift CVE quarantine
```

The fleet view shows posture distribution, currently quarantined projects,
projects in `at_risk_running` (dangerously-disable-quarantine with active
findings), active suppression counts, and the migration grace state.

The per-project view shows posture, quarantine state (with the triggering
CVE if applicable), the latest scan disposition per finding, and the
project's active suppressions.

## Recovering a quarantined project

1. **Inspect what triggered the quarantine:**

   ```
   boxmunge security <project>
   ```

2. **Decide:** wait for an upstream fix (and re-run when it's released),
   or suppress the CVE with a documented reason after review.

3. **If suppressing:**

   ```
   boxmunge security suppress <CVE> --project <project> --until 2026-08-01 \
     --reason "Endpoint not exposed in our config; vulnerable code path unreachable."
   ```

4. **Lift the quarantine:**

   ```
   boxmunge security resume <project>
   ```

   `resume` re-scans the image, regenerates the project's Caddy config,
   restarts the containers, and runs the smoke test. It refuses to lift
   the quarantine if any finding still meets the project's posture
   threshold:

   ```
   ERROR: Cannot resume — CVE-2026-5678 (Critical) would still quarantine.
     Either suppress it (boxmunge security suppress) or wait for upstream fix.
   ```

   Surface and address the remaining finding before retrying.

This is distinct from `boxmunge resume` (which lifts a manual `pause`).
Quarantine state is separate from pause state — `boxmunge up` does not
auto-resume CVE-quarantined projects across reboot.

## Out of scope (v0.6.0)

These are deferred to later releases:

- Web dashboard CVE view (CLI only in v0.6.0).
- VEX (Vulnerability Exploitability eXchange) document generation/consumption.
- CVSS-based numeric scoring (categorical Low/Medium/High/Critical only).
- Auto-suppression heuristics (e.g., "Linux kernel CVE against Alpine,
  known not applicable").
- Pluggable scanner interface; v0.6.0 is Trivy only.
- Trivy DB mirroring / offline support.
