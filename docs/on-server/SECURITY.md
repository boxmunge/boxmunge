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

## Wildcard hosts and routing isolation

boxmunge rejects wildcard host entries (e.g. `*.example.com`) by default. On a single Caddy instance shared between projects, a wildcard on one project can capture traffic intended for adjacent projects whose plain hostnames happen to fall under that wildcard. boxmunge runs single-tenant — every project on a host is owned by the same operator — so this is a footgun, not a multi-tenant breach. We still gate it behind an explicit opt-in:

```yaml
allow_wildcard_hosts: true
hosts:
  - "*.example.com"
```

Without `allow_wildcard_hosts: true`, manifest validation refuses to deploy. With it set, you accept that any plain `foo.example.com` belonging to another project on the same host is at risk of being shadowed by the wildcard's routes. Don't enable it on a host where you intend to operate adjacent projects under the same parent domain.

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

## Supply-chain protection (release signing)

Every boxmunge release tarball's `SHA256SUMS` is keyless-signed by the GitHub Actions release workflow using Sigstore (Fulcio + Rekor). The upgrade shim verifies that signature against a pinned certificate identity (the release workflow on a `vX.Y.Z` tag of this exact repo, issued by GitHub's OIDC) BEFORE running `sha256sum -c`. cosign is hard-required: if it's missing, the upgrade aborts noisily rather than degrading to checksum-only. This breaks the circularity of "verify the tarball with a hash file pulled from the same release" — an attacker who replaces both files in lockstep can no longer pass verification without also forging a Fulcio certificate tying the signature to this repo's release workflow. An unsigned release (e.g. one where the cosign install step in CI failed) will be refused by the shim, not silently installed.
