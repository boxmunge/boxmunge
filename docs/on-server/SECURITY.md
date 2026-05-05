# boxmunge Container Security Model

Per-project container hardening — what protects you by default, how to relax it
when you must, and what's coming in future tiers.

## TL;DR for agents

- **Defaults are silent.** Every service deployed via boxmunge runs with
  `no-new-privileges`, Tini init, a 512-process ceiling, and a list of
  dangerous Linux capabilities dropped. You do nothing to get this.
- **Don't disable hardening to "ship faster".** If a specific protection
  is in your way, relax that one field. Setting `profile: off` requires
  a reason and triggers a repeated deploy-time warning on every operation.
- **Use `boxmunge security <project>` to verify the effective posture.**
  Run with `--json` for a machine-readable view.

## Profiles

| Profile | Behaviour |
|---|---|
| `default` | All v0.5 hardening applied. The silent floor. |
| `off` | Nothing applied. Requires `reason`. Triggers deploy warnings. |
| `strict` (reserved) | Tier 3 — adds `read_only` rootfs, non-root user, `cap_drop: ALL`. Requires project changes. |
| `paranoid` (reserved) | Tier 8 — adds auto-generated seccomp + user-namespace remapping. |

The profile ladder is `off → default → strict → paranoid`. v0.5 ships with `default` and `off` only. The reserved names will be honoured in future tiers; manifests using them today fail validation rather than silently doing nothing.

## What `default` applies

Per service, in the generated `compose.boxmunge.yml`:

```yaml
security_opt: ["no-new-privileges:true"]
init: true
pids_limit: 512
cap_drop:
  - NET_ADMIN
  - SYS_PTRACE
  - SYS_MODULE
  - SYS_RAWIO
  - SYS_TIME
  - SYS_BOOT
  - MAC_ADMIN
  - MAC_OVERRIDE
  - MKNOD
  - AUDIT_WRITE
  - WAKE_ALARM
  - BLOCK_SUSPEND
  - LEASE
  - NET_RAW
cap_add: []
```

These caps are NOT in Docker's default deny list, but are dangerous and rarely needed by application code. `NET_RAW` is the only borderline drop — it powers `ping`, `traceroute`, and a few health-check scripts. If your app actually needs it, opt back in via `cap_add`.

## Relaxing a single protection (preferred)

Add to manifest:

```yaml
security:
  cap_add: [NET_RAW]      # re-add NET_RAW project-wide
  pids_limit: 2048        # raise the process ceiling
```

Per-service:

```yaml
services:
  worker:
    security:
      cap_add: [NET_RAW]
      pids_limit: 4096
```

## Turning the whole posture off (last resort)

```yaml
services:
  honeypot:
    security:
      profile: "off"
      reason: "intentional honeypot service, see issue #42"
```

Note the quotes around `"off"`. PyYAML parses unquoted `off`, `on`, `yes`, `no`
as YAML 1.1 booleans, and `profile: off` would silently become
`profile: False`. The validator catches that and tells you to quote it, but
get into the habit of writing it correctly the first time.

Requirements:

- `reason` must be a non-empty string. Schema validation rejects missing or blank reasons.
- Every `stage`, `promote`, `deploy`, `prod-deploy`, `resume`, and `upgrade` will print a multi-line `[WARNING] SECURITY OFF` message including the reason. This is by design and not silenceable except by removing `profile: off`.
- `boxmunge health` raises a warning for any project with services on `profile: off`.

## Inheritance and resolution

For each (project, service):

1. Start from the project's `security.profile` (or `default` if no block).
2. Apply project-level field overrides on top.
3. If the service has a `security:` block:
   a. Its `profile` (if set) replaces the project profile for this service only.
   b. Its individual fields apply on top.
4. `cap_add` is subtracted from `cap_drop` at the end.

Two invariants:

- **Absence inherits.** Omitting a field never disables a protection.
- **Disabling is explicit.** Set `no_new_privileges: false`, `pids_limit: 0`, etc.

## What is NOT applied in v0.5 (and why)

| Not applied | Reason | When |
|---|---|---|
| `read_only: true` rootfs | Breaks projects that write outside `data/`. | Tier 3 (`strict`). |
| Non-root user enforcement | Many container images run as root. | Tier 3 (`strict`). |
| `cap_drop: ALL` | We drop only the dangerous subset. Full drop breaks several apps. | Tier 3 (`strict`). |
| Default memory/CPU caps | Existing `limits` field is the user's tool. | Never imposed by default. |
| Egress allowlist | Default-deny outbound needs network design. | Tier 4. |
| Custom seccomp profile | Docker's default seccomp already applies. | Tier 8 (`paranoid`). |
| Image scanning, digest pinning | Detection-without-remediation is a UX trap. | Tier 2 (v0.6) with auto-remediation pipeline. |

See `agent-help architecture` and the on-server `TRUST_MODEL.md` for adjacent context (host hardening, restricted shell, platform container hardening).
