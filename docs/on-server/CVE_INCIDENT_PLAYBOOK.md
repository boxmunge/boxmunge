# CVE Incident Playbook — for AI agents

You are the agent on a boxmunge box. A CVE alert just landed, or you're doing
a scheduled check. This playbook walks through the full incident: interrogate,
understand, decide, record. The deploy shell is your only interface — every
step here is via `security` subcommands.

For the full policy reference (posture tiers, hardening penalty, decision
matrix, suppression file format), see `agent-help cve`.

---

## Triage

The five things that produce a CVE alert:

| Alert title prefix | What it means |
|---|---|
| `[boxmunge:<p>] QUARANTINED — <CVE>` | Project taken offline by policy. Maintenance page is being served. |
| `[boxmunge:<p>] [STILL RUNNING]` | Would have quarantined but `dangerously_disable_quarantine: true`. Project is up at known risk. |
| `[boxmunge:<p>] <CVE>` (no severity prefix) | Sub-threshold finding. Informational only. |
| `[boxmunge:<p>] Suppression expired` | A previously-suppressed CVE is now an active finding. Quarantine queued for next scan. |
| `[boxmunge] CVE policy enforcement begins in <N>h` | One-time migration grace heads-up after upgrade. Affects the whole fleet. |

If you got an alert, run these two commands first — they tell you everything.

```
security                    # Fleet view: who else is affected?
security <project>          # Per-project: headline CVE + every disposition
```

For machine-parseable output add `--json` to either.

What to read in `security <project>`:

- `status` — `NORMAL` / `QUARANTINED` / `AT_RISK_RUNNING`
- The `Findings (N)` list — sorted by effective severity desc. The
  `[QUARANTINE]` and `[STILL_RUNNING_AT_RISK]` rows are what need action.
- The `explanation` per finding — tells you base severity, effective
  severity, posture, why this disposition was reached.
- `Active suppressions:` — what's already been signed off.

---

## Decision tree

For every finding marked `QUARANTINE` or `STILL_RUNNING_AT_RISK`:

### 1. Is there an upstream fix?

If `disposition == IGNORED_FIXED`, the auto-update path picks it up on
next image rebuild. No action. Move on.

### 2. Is it already suppressed?

If `disposition == SUPPRESSED` but `until` is approaching, decide whether to
extend. To extend: `security unsuppress` then `security suppress` with a new
date and a freshly-reviewed reason. Don't blanket-extend without re-reading
the CVE — if anything changed upstream, the original reasoning may be stale.

### 3. Is it actually exploitable in our deployed config?

**This is the only judgment call that matters.** The scanner doesn't know
context. You do (or you can find out).

> **v0.7.1+ note:** the engine now reads CVSS Attack Vector from Trivy
> output. Under non-paranoid postures (`relaxed` / `balanced` / `strict`),
> AV:Local / Adjacent / Physical and AV-unknown findings are auto-routed
> to informational — they aren't reachable from the network surface a
> hardened web container exposes. So if you see a `QUARANTINE` row, the
> AV is already known to be Network (or the project is on `paranoid`
> posture). The AV:L "is this exploitable from network" branch of the
> reasoning below is now handled automatically. Most "high but not
> exploitable" suppressions written under v0.6 / v0.7.0 are no longer
> needed for AV:L findings — operators MAY clean up moot suppressions
> periodically; they're harmless if left in place.

#### What to read

For the headline finding, the `explanation` field tells you which package
and severity. The `primary_url` (visible in `security <project> --json`)
links to the upstream advisory.

Cross-check with what you know about the project:

| Signal | Likely interpretation |
|---|---|
| Package is a build-time tool (pip, npm, apt) | Runtime container probably doesn't invoke it. Often non-exploitable. |
| Vulnerable code path requires user-initiated action | If your service has no such surface, often non-exploitable. |
| Network attack vector + project not internet-exposed | Often non-exploitable; suppress with reason citing the closed surface. |
| Local attack vector (AV:L) | Already auto-informational under non-paranoid posture. Just keep an eye on it; no action needed. |
| Critical RCE on a runtime-invoked dependency | Treat as exploitable. |
| You can't tell | **Escalate.** See section 4. |

What you can interrogate to inform the decision:

```
status                          # Ports, hosts, exposure surface
log --tail 100 --json           # Recent operational events
security --json | jq '.at_risk_running, .quarantined'
                                # Anything else broken at the same time?
```

What you cannot interrogate (no shell access): the package source, the
running process tree, network connections. If those would change your
decision, escalate.

### 4. When to escalate

Stop and write the operator a clear message if any of these hold:

- You cannot determine exploitability with high confidence.
- The suppression you'd add would extend an existing suppression past
  ~6 months — that's a "we're never fixing this" signal that needs a human.
- Multiple projects are quarantined at once (fleet-wide upstream issue).
- The CVSS is 9+ AND the package is a runtime dependency.
- Caddy itself is quarantined (entire fleet offline).
- The runtime config has changed in ways relevant to exploitability since
  the existing suppression was reviewed.

Escalation message template:

> Project `<name>` has `<CVE-ID>` (`<severity>`) at `<disposition>`.
> Package: `<package>`. Effective severity: `<base> → <effective>`.
> I cannot determine with confidence whether it is exploitable in our
> deployed config because `<specific gap>`. Recommendation: human review
> before suppress / resume / accept-quarantine.
> Trivy: `<primary_url>`.

---

## Acting

### A. Suppress (not exploitable)

> **v0.7.1+:** if the finding is AV:L / Adjacent / Physical and the project
> is on a non-paranoid posture, it's already informational — no suppression
> needed. Suppression is the right answer for **AV:N** findings that are
> documented-not-exploitable in your specific config (closed endpoint,
> non-default flag, parser path you don't reach). On `paranoid` posture,
> suppression remains the answer for AV:L findings you've reviewed.

```
security suppress <CVE-ID> --project <project> \
    --until <YYYY-MM-DD> \
    --reason "<concrete why>"
```

The `--reason` is the audit trail. Future-you reading it in 90 days needs to
understand the call. Bad reasons:

- "not exploitable"
- "doesn't apply"
- "false positive"
- "reviewed"

Good reasons name the attack vector and the specific condition that doesn't
hold:

- "pip archive-handling CVE. pip is build-time only in this image; the runtime
  container runs gunicorn and never invokes pip. Attack vector requires
  user-initiated install with malformed archive — not reachable from the
  served HTTP surface."
- "OpenSSL CVE in TLS handshake path. We terminate TLS at Caddy (separate
  container, separate image); this app never opens a TLS socket of its own."
- "libxml2 CVE in XML external entity handling. Service does not parse
  user-supplied XML — only JSON request bodies. Audited routes in app.py
  on 2026-05-07."

Choose `--until` as the deadline by which you'd reasonably re-check upstream
for a fix. 30-90 days for low-impact CVEs; 14-30 for higher-severity.

After suppressing a finding that was QUARANTINE-disposition: bring the
project back online.

```
security resume <project>
```

`resume` re-scans, refuses if any quarantine-level finding remains,
regenerates Caddy, restarts containers, runs smoke.

### B. Tighten hardening (exploitable, low impact, can drop penalty)

Adding `read_only: true` to a service drops the hardening penalty by 1
and can move the effective severity below the posture threshold.
read_only is NOT in boxmunge's default overlay (it's a strict-profile
feature), so the user must opt in by declaring it.

Do not redeclare `security_opt: ["no-new-privileges:true"]` in user
compose — the default-profile overlay already sets it, and Compose
rejects duplicate list items at merge time. The CVE-policy penalty
calc is overlay-aware (v0.6.2+), so relying on the overlay's
no-new-privileges does not incur a penalty.

This is a manifest/compose change — you don't have file-edit authority
in the deploy shell. Hand off:

> Project `<name>` is quarantined on `<CVE>`. The CVE is exploitable but
> low-impact, and the hardening penalty (+`<n>`) is what pushed effective
> severity above threshold. Recommend: edit `services/<name>/compose.yml`
> to add `read_only: true` (and a `tmpfs: ['/tmp']` if the app writes
> there), rebundle, redeploy. Effective severity should drop to `<X>`,
> below the `<posture>` threshold.

### C. Accept the quarantine

If exploitable, no upstream fix coming, and tightening hardening won't help:
leave the project quarantined. Maintenance page stays up. Monitor for the
upstream fix:

```
# Check periodically
security <project>
```

Once a fix lands (auto-update will pick it up on next image build), resume.

### D. dangerously_disable_quarantine

Use only when uptime matters more than reactivity AND blast radius is
acceptable on compromise (no secrets, no PII, redeployable from clean
source). Validator requires `read_only: true` on every service — this is
the deal: you accept the CVE risk in exchange for non-persistent compromise.

This requires a manifest edit (`security.dangerously_disable_quarantine: true`)
and ensuring read-only rootfs across services. Hand off to operator.

---

## Recording

Every action leaves a trail. The trail IS the record — there's no separate
incident log to write.

| What you did | Where it's recorded |
|---|---|
| `security suppress` | `<project>/security/suppressions.yml`, visible via `security <project>` |
| `security unsuppress` | Same file, entry removed; ops log records the change |
| `security resume` | Quarantine state file removed; ops log records the resume |
| `security scan` | `state/scans/<project>.json`, visible via `security <project> --json` |
| Quarantine fired | `state/deploy/<project>.quarantined.json`; ops log entry |
| Pushover alerts (if configured) | Operator's phone |

Read the trail back via:

```
log --tail 50              # Last 50 ops events
log --tail 50 --json       # Same, parseable
security <project>         # Current dispositions + active suppressions
```

---

## Things you cannot do (and what to do instead)

| Want to | Can't (deploy shell) | Do instead |
|---|---|---|
| Read suppressions.yml directly | No `cat` | `security <project>` shows active entries |
| Run `trivy` against an image | No subprocess access | `security scan <project>` does it via boxmunge |
| Edit compose.yml | No file editor | Escalate or rebundle locally and redeploy |
| Disable the cron timer | No `systemctl` | Escalate — if the timer is misbehaving, that's a supervisor concern |
| Read state/* files | No filesystem access | `--json` views surface everything an agent needs |

---

## Routine check (no alert)

Once a week, even with no alerts:

```
security                            # Fleet — any drift?
log --tail 100 --json | <scan for security events>
```

What to flag:

- Suppressions expiring within 7 days (`security <project>` shows `until`)
- Projects in `at_risk_running` for more than 90 days without a suppression
- Repeated scan failures in the ops log (Trivy DB issues, image not pullable)
- Migration grace still active after the 24h window (something's stuck)

If anything looks off and the path forward isn't obvious from this playbook:
escalate. Better to under-act than to over-act on incomplete information.
