# boxmunge CVE Policy

How boxmunge handles CVEs published against deployed images: daily scanning,
the trust ladder, CISA KEV integration, posture-based quarantine, suppression
workflow, and recovery.

## TL;DR for agents

- **Daily scan via Trivy.** Every project's deployed images are scanned at
  03:00 system time (±30 min jitter); also on every deploy and image update.
- **Posture per project (default `balanced`).** Four tiers form a trust ladder
  — `relaxed` quarantines only on CISA KEV, `balanced` (default) quarantines
  on KEV or a distro-acknowledged High + AV:N finding, `strict` extends that
  net to Medium, `paranoid` uses NVD severity with no distro trust.
  Set in the manifest under `security.posture`.
- **Trust the distro.** Below `paranoid`, the engine treats the distro's own
  triage as authoritative. A CVE the distro marked `will_not_fix`,
  `fix_deferred`, `not_affected`, or `under_investigation` is informational
  regardless of NVD severity — the distro already judged it.
- **KEV is an override.** A finding on CISA's Known Exploited Vulnerabilities
  catalog quarantines immediately under every posture. The AV filter, distro
  status, and severity threshold do not apply.
- **Runtime relevance gate (balanced/strict).** A finding against an OS
  package that belongs to a language runtime (`perl`, `ruby`, `php`,
  `python`, `node`, `tcl`, `lua` — the ecosystem names accepted by
  `security.runtimes`, not the OS package names) the project never invokes
  is informational, regardless of distro severity — a Python app cannot run
  a Perl regex bug. Inferred automatically from the image's own dependency
  scan; `paranoid` does not consult it, and KEV still overrides it.
- **Auto-quarantine** when a finding crosses the project's quarantine gate:
  `compose stop` + maintenance page + critical Pushover alert.
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

## The trust ladder

The four postures form a trust ladder, not just severity thresholds. The
governing insight: for every posture below `paranoid`, the distro's own
triage is a first-class, authoritative input. Debian triages CVEs against
its actual packaged versions and marks findings it judges low-risk as
`will_not_fix` or `no-dsa` — taking a site offline for those would override
the distro's own verdict without additional evidence.

`relaxed` is the strongest expression of that trust: the site only goes dark
for active exploitation. `paranoid` is the opposite: it behaves like the
pre-trust-ladder engine, using NVD severity with no distro trust and no AV
filter.

| Posture | Quarantines when (no fix, not suppressed) | Severity source |
|---|---|---|
| **relaxed** | CVE is on **CISA KEV** — nothing else. Pure last resort. | — |
| **balanced** *(default)* | On **KEV** OR distro `Status: affected` + **distro** severity ≥ High + `AV:N` | Debian/vendor |
| **strict** | On **KEV** OR distro `Status: affected` + **distro** severity ≥ Medium + `AV:N` | Debian/vendor |
| **paranoid** | Anything ≥ Medium over threshold — no AV filter, no distro trust, NVD severity (pre-trust-ladder behavior). KEV can still escalate. | NVD |

`balanced` stays the out-of-the-box default. The residual net it keeps
(distro-acknowledged High, AV:N, no fix) is genuine: Debian issues a DSA
quickly for those, so catching them is meaningful — and rare enough not to
create the false-quarantine problem that motivated this design.

`relaxed` and `balanced` differ meaningfully. A distro-acknowledged, High,
unpatched, network-reachable CVE takes a `balanced` site down but not a
`relaxed` one. If that distinction matters for a project, choose consciously.

### When to use `paranoid`

Use `paranoid` when you want the pre-trust-ladder behavior: every
above-threshold finding quarantines regardless of attack vector or distro
verdict. Suitable for:

- Services running locally-attackable code paths exposed via privileged
  guest invocation (e.g. the web container shells out into another pid
  namespace where AV:L is genuinely reachable).
- High-trust environments where you would rather over-quarantine than
  miss any above-threshold finding the operator hasn't yet reviewed.

The expected default for typical web/api containers is `balanced` with
the distro trust active. AV:L findings and distro-deprioritized findings
on hardened web surfaces are not worth taking services down for.

## Per-finding decision order

For every finding, `evaluate_finding` runs these gates in order:

1. **Fix available** → `IGNORED_FIXED`. Deferred to the auto-update path.
2. **Active suppression** → `SUPPRESSED`. Skipped until suppression expiry.
3. **On CISA KEV** → `QUARANTINE`. KEV is an override: active exploitation
   bypasses the AV filter, distro-status routing, and the severity threshold.
   Applies to every posture. (A KEV finding can still be suppressed via step 2
   if the operator has reviewed it.)
4. **Unknown severity** → `INFORMATIONAL`. The engine cannot reason about a
   severity it does not recognize; reporting only.
5. **Paranoid short-circuit** — under `paranoid`, skip steps 6–10 and compare
   the NVD severity directly against the Medium threshold with no AV filter.
   This is the pre-trust-ladder behavior, unchanged.
6. **Relaxed short-circuit** — under `relaxed`, quarantine is KEV-only (already
   handled at step 3). Every non-KEV finding is `INFORMATIONAL` regardless of
   distro severity — the most hands-off tier, for operators who accept
   severity-based risk. Raise the posture to `balanced`/`strict` for
   distro-severity-based quarantine.
7. **Irrelevant runtime** (balanced/strict) — the package belongs to a
   language runtime the project never invokes → `INFORMATIONAL`. Placed
   ahead of the distro-status gates below: all of them produce
   `INFORMATIONAL` too, so the ordering doesn't change the outcome, but this
   reason is the most informative one to surface. See "Runtime relevance
   gate" below.
8. **Distro deprioritized** (balanced/strict) — `Status ∈ {will_not_fix,
   fix_deferred, not_affected, under_investigation}` → `INFORMATIONAL` with a
   loud alert. The distro already judged the finding low-risk; the site stays
   up. The alert quotes the distro status and severity so the operator can see
   exactly why.
9. **No distro verdict** (balanced/strict) — `distro_severity(finding) is None`
   (only NVD/GHSA data; the distro issued no rating) → `INFORMATIONAL`. Below
   `paranoid`, the engine does not quarantine on an NVD rating the distro never
   echoed. Language-level vendored findings that the OS package tracker never
   touched fall here.
10. **AV filter** (balanced/strict) — CVSS Attack Vector is not Network → `INFORMATIONAL`.
   Retained from v0.7.1. By this step the distro verdict and severity are
   already authoritative noise gates; the AV filter is a secondary reducer for
   findings that passed distro triage but are not network-reachable.
11. **Threshold comparison** against the distro severity (elevated by the
   hardening penalty, using the posture threshold from the trust ladder table)
   → `QUARANTINE` / `STILL_RUNNING_AT_RISK` / `INFORMATIONAL`. Reached only by
   `balanced`/`strict` with a distro severity and a `Status` that is not one
   of the deprioritized statuses in step 8: `affected`, `end_of_life`, or a
   missing/unrecognised status. A missing status is not a distro verdict that
   the finding is low-risk, so it fails closed and is threshold-compared like
   `affected`.

### Decision matrix summary

| Condition | Outcome |
|---|---|
| Fix available upstream | `IGNORED_FIXED` — auto-update path |
| Active suppression matches the CVE | `SUPPRESSED` — skip until expiry |
| CVE is on CISA KEV | `QUARANTINE` — override; no further checks |
| Severity unknown | `INFORMATIONAL` |
| Posture is `paranoid` | NVD threshold gate (step 5 above) |
| Posture is `relaxed` (non-KEV finding) | `INFORMATIONAL` — relaxed is KEV-only |
| Package is a language runtime this project never invokes | `INFORMATIONAL` — irrelevant runtime |
| Distro marked `will_not_fix` / `fix_deferred` / `not_affected` / `under_investigation` | `INFORMATIONAL` — distro deprioritized |
| No distro rating (NVD/GHSA only) | `INFORMATIONAL` — no distro verdict |
| CVSS Attack Vector is not Network | `INFORMATIONAL` — not network-reachable |
| Distro severity (+ hardening penalty) ≥ threshold | `QUARANTINE` (or `STILL_RUNNING_AT_RISK` if quarantine disabled) |
| Distro severity (+ hardening penalty) < threshold | `INFORMATIONAL` |
| `dangerously_disable_quarantine: true` | `STILL_RUNNING_AT_RISK` instead of `QUARANTINE` |

### `end_of_life` status

A finding with `Status: end_of_life` is **not** in the distro-deprioritized
bucket. EOL means the distro will never ship a fix — that is a more dangerous
signal, not less. On Debian 13 stable it should not appear; if it does, it
falls through to step 11 (the threshold gate) alongside `Status: affected`.

## CISA KEV feed

### Source and refresh

The KEV feed is CISA's Known Exploited Vulnerabilities catalog:

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

`refresh_kev()` is called once per scan run alongside `refresh_db()` (the
Trivy DB refresh), so the KEV catalog stays as fresh as the scan that consumes
it. There is no dedicated timer in v1; the daily scan cadence is sufficient.

After refresh, the catalog is loaded and a single `kev_lookup` predicate is
threaded into every project's `evaluate_finding` call for that run — the
exploitation signal is consistent fleet-wide within a scan run.

### Staleness and fail-safe

The catalog is considered stale when its `fetched_at` timestamp is older than
`KEV_MAX_AGE_DAYS` (currently 8 days — a week of fetch failures before the
gate degrades).

**Fail-safe: toward uptime, never toward quarantine.** When the catalog is
missing or stale, `is_known_exploited` returns `False`. The site is not taken
down on an exploitation signal that cannot currently be verified.

Staleness is never silent. When a scan run detects a stale or missing catalog,
it:
1. Logs a WARNING with the last fetch timestamp (if any).
2. Fires a single priority-1 Pushover alert per run:
   `KEV feed stale — exploitation-based quarantine is degraded`.

This alert fires once per scan run, not once per finding, to avoid alert
storms. The degradation must not go unnoticed — the `relaxed` tier's only
quarantine protection depends on the KEV feed.

## Runtime relevance gate

The trust ladder grades how bad a CVE is. Until this gate, it never asked
whether the project could even run the affected code. Two production
outages made the gap concrete: a Python/FastAPI project got quarantined —
`compose stop`, maintenance page, critical alert — over a Critical CVE in
`perl-base`. The project has no Perl anywhere in its request path; the
package was there because it ships in the base image. A Python app cannot
execute a Perl regex bug, however Critical Debian rates it. Below
`paranoid`, a finding against an OS package that belongs to a language
runtime the project never invokes is now `INFORMATIONAL` instead of
threshold-compared (step 7 in the decision order above).

### What counts as "a language runtime"

The gate matches against a narrow, hand-picked table of **standalone
interpreter packages** — not every package a language ecosystem ever
touches:

| Runtime | OS package patterns |
|---|---|
| perl | `perl`, `perl-base`, `perl-modules-*` |
| ruby | `ruby`, `ruby[0-9]*` |
| php | `php`, `php[0-9]*`, `php-*` |
| python | `python3`, `python3.*`, `python3-*` |
| node | `nodejs` |
| tcl | `tcl`, `tcl[0-9]*` |
| lua | `lua`, `lua[0-9]*` |

Two classes of package are deliberately left out, for opposite reasons:

- **Embeddable interpreter libraries** — `libperl*`, `liblua*`, `libtcl*`,
  `libpython3*`, and friends — are absent on purpose, not by oversight.
  `redis-server`, `haproxy`, and `nginx-extras` link `liblua`; `mod_perl`
  links `libperl`. A CVE in one of those libraries *is* reachable from a
  project written in an entirely different language, so exempting them
  would create exactly the silent-exemption hazard this gate exists to
  avoid. If a future change ever adds these to the table, it must also
  prove those consumers don't link them.
- **Ordinary system libraries** — `openssl`, `libc6`, `zlib1g`,
  `libexpat1`, and so on — are absent because they aren't a language
  runtime at all. A CVE in `openssl` keeps today's quarantine behaviour
  regardless of what the project is written in.

Anything the gate doesn't recognise — an unknown package, a package that
isn't OS-class, a family not in the table — is treated as **relevant**,
i.e. still quarantinable. Drift here causes a missed de-escalation (a
nuisance, fixed by extending the table), never a silent exemption (a
hazard).

### Automatic inference, and the `security.runtimes` override

By default, the project's runtime set is inferred automatically from that
image's own dependency scan: every Trivy `lang-pkgs` **result** type present
(a Python image reports a `python-pkg`/`pip` result, a Node image reports
`npm`/`node-pkg`, and so on) maps to a runtime. This is read from the scan
*result*, not from *findings* — Trivy still emits the lang-pkgs result row
even when a project's own dependencies carry zero vulnerabilities, so a
fully-patched project infers its runtime correctly instead of losing the
gate's protection the moment its dependencies are clean.

An operator can override inference with an optional manifest key:

```yaml
security:
  runtimes: [python]
```

`runtimes` must be a non-empty list drawn from: `python`, `node`, `go`,
`ruby`, `php`, `java`, `rust`, `dotnet`, `perl`, `tcl`, `lua`. A declaration
**replaces** inference rather than adding to it — the project's runtime set
is exactly what you listed, nothing more. An empty list is rejected at
manifest-validation time rather than silently accepted: `runtimes: []`
would mark every runtime as foreign to the project and exempt all of them,
which is almost certainly a manifest mistake (a stray empty list, an unset
templating variable) rather than an intentional "trust nothing" statement.
A non-list value — a bare string, a mapping, a bool, an int — is rejected
the same way, because several of those shapes would otherwise be silently
misinterpreted (a string iterates into individual characters; a mapping
iterates into its keys).

**Caveat for multi-image projects.** The runtime set above is computed
*per image*, but `security.runtimes` is declared *per project*. On a
project with more than one image — say a Python `web` service and a Node
`worker` service — declaring `runtimes: [python]` replaces inference for
**both** images, silently exempting `nodejs` CVEs in the worker that
inference alone would have caught. Declaring can therefore make a
heterogeneous project *less* safe than declaring nothing at all. Prefer
omitting `security.runtimes` and relying on per-image inference; if you do
declare it, list every runtime used anywhere in the project, not just the
one you're thinking about.

**An empty inferred set can mean "no runtime" or "no visible manifest" —
inference cannot tell them apart.** A static site served by nginx
legitimately infers zero runtimes: every language family is genuinely
foreign to it. But an image that installs its runtime WITHOUT a
Trivy-visible lang-pkgs manifest lands in that exact same bucket —
`apt-get install python3 python3-flask` with no pip layer, a PHP image with
no `composer.lock`, a conda environment (Trivy's `conda-pkg` type isn't
mapped to an ecosystem at all; see below) — and inference has no way to
distinguish "runs nothing" from "runs something Trivy couldn't see." When
that happens, the gate exempts the project's OWN runtime: a Critical,
distro-affected `python3` finding would be de-escalated exactly like a
genuinely-foreign `perl-base` finding would be. boxmunge logs a warning
(component `cve-scan`) when it detects this — a de-escalation against an
OS-class runtime package with an empty, *inferred* (not declared) runtime
set — but the remedy is on the operator: declare `security.runtimes`
explicitly for any image whose runtime isn't installed through a
Trivy-recognised language package manager.

Relatedly, an unrecognised Trivy lang-pkgs `Type` (one absent from
`relevance._TRIVY_TYPE_TO_ECOSYSTEM` — `conda-pkg`, `pipenv`, and `uv` are
current examples) contributes no ecosystem to inference, which *shrinks*
the inferred runtime set rather than growing it. This is the opposite bias
from an unrecognised OS package family (which safely defaults to
"relevant"), so boxmunge logs a warning when a scan encounters one. Extend
the mapping table, or declare `security.runtimes`, to close the gap.

### Interaction with the rest of the trust ladder

- **KEV still overrides.** A finding on CISA's KEV catalog quarantines
  regardless of runtime relevance — active exploitation bypasses this gate
  the same way it bypasses the AV filter and distro-status routing.
- **`paranoid` does not consult it at all.** The paranoid short-circuit
  (step 5) runs before this gate; paranoid stays byte-for-byte its
  pre-relevance-gate behavior.
- **The gate only ever de-escalates.** It has exactly one output,
  `INFORMATIONAL`; it can never turn a finding that would otherwise be
  informational into a quarantine.
- **The verdict doesn't expire.** Every other informational route in this
  document — distro-deprioritized, no-distro-verdict — is a live read of
  the distro's tracker and can flip to `QUARANTINE` the day Debian revises
  its verdict. Runtime relevance isn't: it's a property of what the
  project runs, not of anyone's triage, so it holds until the project's own
  dependency footprint changes.

## Effective severity = base + hardening penalty

The scanner reports a base severity (Low / Medium / High / Critical). If
the project has weakened the boxmunge hardened defaults, that base is
elevated by a hardening penalty before being compared against the
posture threshold.

| Hardening weakened | Penalty |
|---|---|
| `read_only: false` (writeable rootfs, **explicit user opt-out**) | +1 |
| `no-new-privileges` removed or set to false | +1 |
| `cap_add` beyond image defaults (any non-empty list) | +1 |
| `privileged: true` | +2 (already rejected by validator) |

Penalty is capped at +2 total. The audit ledger and per-finding
explanation show the elevation reason explicitly so you can see why a
Medium CVE quarantined a project running on `strict` posture.

For non-paranoid postures, the penalty applies to the **distro** severity
at step 11. For `paranoid`, the penalty applies to the **NVD** severity.

Rationale: running with read-only rootfs disabled means a Medium CVE
behaves more like a High one in practice — the policy treats it that way.

### v0.8 hardening defaults

As of v0.8, boxmunge's default-profile overlay applies `read_only: true`
and `tmpfs: ['/tmp']` by default. Apps that legitimately need writable
rootfs must declare `read_only: false` explicitly in their user
`compose.yml`, which incurs the +1 penalty above. Missing the field
means the overlay's `read_only: true` default applies — no penalty.

This inverts the v0.7.x semantics where missing `read_only` was
penalised even though the system never actually enforced it. v0.8 is
the closing of that asymmetry: the platform now provides what it
penalises operators for omitting.

The overlay generator's user-wins rule: if your `compose.yml` declares
`read_only` (true or false) on a service, the overlay omits its
own `read_only` fragment for that service. Compose merge then leaves
your literal value alone — no merge conflict, no need for a redundancy-
rejection rule. The same rule applies to `tmpfs: ['/tmp']`: if you
declare a `tmpfs` or `volumes` entry that targets `/tmp`, the overlay
omits its own.

### Overlay-aware penalty (v0.6.2)

boxmunge's default-profile overlay enforces `no-new-privileges` at
runtime, applied via the generated `compose.boxmunge.yml`. The hardening
penalty calculator is overlay-aware: projects that don't redeclare
`security_opt: ["no-new-privileges:true"]` in their user `compose.yml`
are NOT penalised for it — the overlay already protects them. (Re-
declaring it in user compose would trigger a Compose merge duplicate-
rejection error anyway; see the v0.6.3 dedupe note in
"Recommendations" below.)

The same overlay-aware logic applies to `read_only` from v0.8: a
project that doesn't redeclare `read_only` in user compose is treated
as fully hardened (the overlay provides it). Only an explicit
`read_only: false` in user compose triggers the +1 penalty.

### v0.9 writable: surface and the penalty

The v0.9 `writable:` block (schema 3) is orthogonal to the read-only-
rootfs penalty. Declaring `writable.ephemeral` and/or
`writable.persistent` does NOT incur a CVE penalty — the service is
still on a read-only rootfs, just with operator-declared writable
sub-paths.

`writable.external: true` (operator delegates writability to
compose.yml entirely) also incurs no penalty by itself, provided
`read_only: true` still applies. The deploy-time `[INFO]` warning is
the visibility signal. Should the operator additionally declare
`read_only: false` in compose.yml for an external service, the +1
penalty for explicit read-only opt-out attaches as normal.

The `boxmunge security <project>` output surfaces the per-service
writable state (default / manifest-managed / externally-managed)
alongside the hardening fragment for full visibility of the
service's silent-floor posture.

## Configuring posture (manifest.yml)

`posture` and `dangerously_disable_quarantine` live at the project level
only — they are not per-service settings. So does `runtimes` — see
"Runtime relevance gate" above for what it does and its multi-image caveat;
omit it unless you have a specific reason to override inference.

```yaml
security:
  posture: balanced                       # default if absent
  dangerously_disable_quarantine: false   # default if absent
  # runtimes: [python]                    # optional; overrides inference
```

The compose validator rejects:

- `dangerously_disable_quarantine: true` on a project where any service
  does not set `read_only: true`. Rationale: if you've told us not to
  react to compromise, the read-only rootfs is the last line of defense
  against post-exploit persistence. The trade is uptime over reaction;
  the read-only rootfs is the price.
- `posture: strict` on a project where any service does not set
  `read_only: true`. Strict posture without read-only rootfs is incoherent.
- Any `posture` value other than `relaxed`, `balanced`, `strict`, or `paranoid`.

These cross-validators run on every entry point that materialises a
project from its manifest+compose: `prod-deploy`, `stage`, `promote`,
`resume`, and the `regenerate_configs` step of `upgrade`. All of them
reject the operation with **exit code 3** if `posture: strict` or
`dangerously_disable_quarantine: true` is set without `read_only: true`
on every service. Exit 3 is the reserved code for compose hardening
rejections (see OPERATIONS.md "Command Exit Codes") so the operator can
distinguish a security-policy failure from a generic operational one.

For background on hardening profiles (`profile: default`, `profile: off`),
see [SECURITY.md](SECURITY.md).

## dangerously-disable-quarantine

Use this when uptime is the dominant concern and the service has nothing
to lose. The motivating example: a public weather aggregator with no
secrets, no user data, no auth. You'd rather be exploited than offline.

The trade is explicit and signed off in the manifest:

- You accept that a quarantine-level CVE on this project will not stop the
  service.
- In exchange, you must run with `read_only: true` on every service —
  any post-exploit persistence has nowhere to land.
- Pushover alerts for findings on this project are prefixed
  `[STILL RUNNING — quarantine disabled by config]`.
- The fleet `--json` view always shows the project under
  `at_risk_running` while it has quarantine-level findings.

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

The file is server-side state in the project directory, written only by
`security suppress` / `security unsuppress`. A bundle that carries a
`security/` directory is refused, so a redeploy cannot replace the
suppressions or erase their history:

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

### Audit trail (v0.7.0)

Every `suppress` and `unsuppress` invocation emits a structured
`cve-suppress` log entry, viewable with:

```
boxmunge log --component cve-suppress
```

The entry records the CVE, project, the operator (`reviewed_by` /
`$USER`), the `until` date, and the reason.

If the same CVE is re-suppressed within **7 days** of an `unsuppress`
on the same project, the CLI prints a `NOTE:` to stderr describing
how long ago the prior unsuppress happened, and the structured log
entry includes `previously_suppressed=true` in its detail. The
combination makes silent extension-of-suppression visible in the
audit trail.

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

The Trivy DB and the CISA KEV catalog are both refreshed before each scan
run (one call each, best-effort). DB-refresh and KEV-refresh failures are
non-fatal: the scan proceeds against whatever cache exists and a warning is
logged. A stale KEV catalog fires a priority-1 alert (see "CISA KEV feed"
above).

Idempotency: the daily cron does not re-fire informational alerts for
unchanged dispositions. Only state transitions (new finding, transition
across threshold, suppression expiry, new quarantine, resume) produce
alerts.

### Per-project scan budget (v0.7.0)

Each project gets a **600-second (10-minute) wall-clock budget** for the
sum of its image scans. If a project exhausts the budget, remaining
images for the current scan are skipped and the project resumes on the
next cron tick. The skip is logged at WARNING with the elapsed time and
the count of skipped images, so a project that consistently overflows
becomes visible in the audit log:

```
boxmunge log --component cve-scan --level warning
```

Rationale: an unbounded scan on a fleet of misbehaving images would
starve the rest of the cron-driven workload. The budget bounds the
worst case while still letting normal scans complete in seconds.

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

Seven categories. Titles only — bodies are self-explanatory.

| Title | Priority |
|---|---|
| `[boxmunge:<project>] QUARANTINED — <CVE> (<severity>)` | high |
| `[boxmunge:<project>] QUARANTINED — <CVE> (actively exploited — CISA KEV)` | high |
| `[boxmunge:<project>] [STILL RUNNING — quarantine disabled by config]` | high |
| `[boxmunge:<project>] <CVE> (<severity>)` (informational, sub-threshold or distro-deprioritized) | normal |
| `[boxmunge:<project>] Suppression for <CVE> expired` | high |
| `[boxmunge] CVE policy enforcement begins in <N>h` (one-time) | normal |
| `[boxmunge] KEV feed stale — exploitation-based quarantine is degraded` | priority-1 |

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

## Quarantine enforcement across the lifecycle (v0.7.0)

Once a project is quarantined, every operational entry point honours
that state until `boxmunge security resume <project>` lifts it. There
is no other path back.

The quarantine record (`state/deploy/<project>.quarantined.json`) says
`action_complete: false` until the maintenance page is routed **and** the
containers are stopped. Every scan of a quarantined project re-asserts the
action — maintenance page, Caddy reload, stop — whatever the scan finds,
so a step that failed (a Caddy reload timeout, a hung `compose stop`) is
retried on the next scan until it completes, and a container started
behind the maintenance page is stopped again. A failed re-assert is a scan
failure for that project: it is reported and the scan exits non-zero.

The behaviour splits into two camps:

**Refuse with exit 1 (operator-initiated mutations):**

- `prod-deploy <project>` / `deploy`
- `stage <project>`
- `promote <project>`
- `resume <project>` (the pause-resume command — distinct from
  `security resume`)

These print an error pointing the operator at `boxmunge security
resume <project>` and abort before touching containers or configs.

**Skip with a logged ops entry (background sweeps):**

- `upgrade` — `regenerate_configs` re-renders the maintenance Caddy
  fragment for the quarantined project (so the maintenance UX
  persists across the upgrade) and `restart_projects` skips
  `compose up` entirely. The project's containers stay stopped.
- `container-update` — pulls + recreates are skipped for quarantined
  projects.
- `backup` / `backup-all` — quarantined projects are skipped (the
  containers are stopped; a backup would dump empty volumes).
- `health` / `check-all` — the quarantine state is reported, no
  smoke test is run, and the project does not contribute to fleet
  failure counts.

In both camps the skip is recorded via `log_operation` and visible in
`boxmunge log --component <component>`. Only `boxmunge security
resume <project>` lifts the quarantine; it re-scans first and fails
closed (see "Recovering a quarantined project" below).

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

   `resume` re-scans every one of the project's current images,
   regenerates the project's Caddy config, restarts the containers, and
   runs the smoke test. It **fails closed**: the quarantine is lifted only
   when the re-scan covered every image and found no quarantine-level
   finding. It refuses, keeps the quarantine, and exits 1 when:

   - any finding still meets the project's posture threshold:

     ```
     ERROR: Cannot resume — CVE-2026-5678 (Critical) would still quarantine.
     ```

   - any image failed to scan (Trivy DB or registry unreachable, for
     example), or every image did;
   - the per-project scan budget ran out before every image was scanned;
   - a service's image cannot be identified (no container to read a digest
     from and no `image:` in `compose.yml`). Declare `image:` alongside
     `build:` for build-only services so the scanner can find them.

   The error lists each image or service that was not covered. Fix the
   cause and retry; an incomplete re-scan is never treated as clean.

This is distinct from `boxmunge resume` (which lifts a manual `pause`).
Quarantine state is separate from pause state — `boxmunge up` does not
auto-resume CVE-quarantined projects across reboot.

## Recommendations

### Don't redeclare overlay-applied hardening (v0.6.3)

Do not redeclare `security_opt: ["no-new-privileges:true"]` in your
user `compose.yml`. The default-profile overlay already sets it in the
generated `compose.boxmunge.yml`; declaring it in user compose
produces a duplicate at compose merge and Docker Compose v2 rejects
the deploy with a duplicate-key error. v0.6.2's penalty calc is
overlay-aware, so the protection counts toward your hardening score
even when it lives only in the overlay — there is no benefit to
redeclaring it, only failure modes.

If you need to *relax* a hardening field, use a `security:` block in
the manifest (see PROJECT_CONVENTIONS.md and SECURITY.md). The
overlay derives from the manifest, so the manifest is the only place
to express intent.

## Out of scope (v0.6.0)

These are deferred to later releases:

- Web dashboard CVE view (CLI only in v0.6.0).
- VEX (Vulnerability Exploitability eXchange) document generation/consumption.
- CVSS-based numeric scoring (categorical Low/Medium/High/Critical only).
- Auto-suppression heuristics (e.g., "Linux kernel CVE against Alpine,
  known not applicable").
- EPSS scoring (an interface seam is reserved; EPSS can layer onto the KEV
  predicate without changing the policy engine's shape).
- Pluggable scanner interface; v0.6.0 is Trivy only.
- Trivy DB mirroring / offline support.
