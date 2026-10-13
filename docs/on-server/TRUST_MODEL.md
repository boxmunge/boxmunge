# boxmunge Trust Model

How boxmunge handles security boundaries, isolation, and access control.

---

## Threat Model

boxmunge's defences are calibrated against a specific set of attackers. Future evolutions may extend this scope; today, severity assessments assume the model below.

### In scope

- **Network-level third-party attackers** — scanning, brute-force SSH, DDoS, malicious traffic targeting the public surface. Mitigations: UFW, CrowdSec, fail2ban, kernel hardening, key-only SSH on a non-default port.
- **Supply-chain compromise of platform releases** — a tampered boxmunge release reaching the box. Mitigations: every release's `SHA256SUMS` is keyless-signed by the GitHub Actions release workflow (Sigstore Fulcio + Rekor), and the upgrade shim verifies the signature against a pinned workflow identity and OIDC issuer before installing. cosign is hard-required — an unsigned release is refused, not silently installed. This closes the prior circularity (where SHA256SUMS and the bundle came from the same release URL and could be replaced in lockstep).
- **Container-escape blast radius** — a compromised user container should not trivially own the host. Mitigations: per-service capability drops, `no-new-privileges`, `pids_limit`, Tini, the host-level platform-container hardening.

### Out of scope (current product)

- **Malicious operators** — anyone with `supervisor` or `deploy` SSH access is fully trusted. The restricted shell is a UX guard against accidents and a reduction in agent context-pollution surface, not a privilege boundary against a determined attacker who already has a key.
- **Malicious agents / MCP tools** — at present, agents and tools invoked through the deploy shell or MCP are treated equivalently to operators. A future product evolution may split agent trust from operator trust; today they are the same principal.

### Single human operator

The same person holds keys to `deploy` and `supervisor`. There is no per-project access control, no per-tenant credential isolation, no audit of "which operator did this." If you need any of those, boxmunge is the wrong tool.

---

## Single-Owner Model

boxmunge assumes all projects on a box belong to one person or entity. There is no per-project access control and no multi-user IAM.

The `deploy` user can operate on any project — this is by design, not a gap. The `supervisor` user has full shell access with sudo.

## What We Isolate

**Platform tooling** runs inside containers for blast-radius containment:

- **Caddy** (reverse proxy) — containerised, read-only filesystem, all capabilities dropped except NET_BIND_SERVICE
- **boxmunge-system** (age, rclone) — containerised, read-only, no capabilities, non-root user

**Secrets** are file-permission isolated — each project's `secrets.env` is mode 600, owned by the deploy user. The deploy user can read any project's secrets (single-owner assumption).

**Logs and state** are per-project by default. The `boxmunge log` command scopes to a single project unless `--all` is passed. This prevents agent context pollution, not security isolation.

## What We Don't Isolate

- **Network** — projects share the `boxmunge-proxy` Docker network and can technically reach each other. Acceptable for single-owner.
- **Docker group** — the deploy user is in the `docker` group, which is effectively equivalent to root on the host (a user can mount the host filesystem via `docker run -v /:/host`). This is an intentional trade-off: the deploy user needs to run `docker compose` for deployments, and Docker's permission model requires group membership. The restricted shell limits what the deploy user does *directly*, but it is not a privilege boundary against a determined attacker who already has SSH access as deploy. Key-only authentication is the real perimeter.
- **Backup encryption key** — the deploy user can read the age identity key at `/opt/boxmunge/config/backup.key` (mode 640, group deploy). This is required for backup and restore operations to work without sudo. An authenticated deploy user can decrypt any backup snapshot.
- **Backups** — the deploy user can trigger backup/restore for any project.

## The Upgrade Shim and the Root Boundary

The upgrade shim (`/opt/boxmunge/bin/boxmunge-upgrade`) runs as root: from the
health and auto-update timers, and from the deploy shell through a scoped sudo
rule. It is the one place where deploy-reachable input crosses into root, so it
treats that input as untrusted even though the docker-group concession above
means deploy is not a hard boundary today.

`/opt/boxmunge/upgrade-state/` is `root:deploy 0770`, because the deploy shell
ends upgrade probation early by removing `probation.json`. Every value the shim
reads from that directory is checked before use:

- The active slot must be exactly `a` or `b`, and must agree with the root-owned
  `env-active` symlink. A disagreement stops the shim rather than letting a
  forged `active-slot` turn the live venv into the "standby" that the next
  upgrade deletes.
- `probation.json` must be a JSON object with a semver `version`, an
  ISO-8601 `expires_at` with a timezone, and a `previous_slot` of `a` or `b`
  that is the current standby slot (promotion deletes it).
- `blocklist.json` must be a JSON object keyed by semver versions.
- None of these files, nor `upgrade.lock`, may be a symlink. The shim writes
  `active-slot` by rename, so a planted link is replaced rather than followed.

Any violation stops the shim with a non-zero exit and an error naming the
file, before the value reaches a path, a URL, or an `rm -rf`. Repair or remove
the file as `supervisor` and re-run.

### What deploy may ask root to do

`/etc/sudoers.d/boxmunge-deploy` grants deploy exactly two shim invocations:

```text
deploy ALL=(root) NOPASSWD: /opt/boxmunge/bin/boxmunge-upgrade auto, /opt/boxmunge/bin/boxmunge-upgrade target *
```

- `auto` discovers the latest release and upgrades to it.
- `target <version>` takes exactly one strict-semver argument. It refuses a
  version that is blocklisted on this box and any version below the installed
  one (`config/version`, which deploy cannot write). Reinstalling the installed
  version is allowed.

Everything else is root-only: `run` (the auto-update timer), `check-probation`
(the health timer), `clear-blocklist`, and `force-target <version>`, the operator
override that skips the blocklist and the downgrade floor. sudo matches the whole
argument string, so `target *` cannot reach `force-target`. The auto-update timer's
`run` applies the same downgrade floor and skips blocklisted versions.

The rule text lives in the shim (`boxmunge-upgrade install-sudoers`). install.sh
calls it, and so does every upgrade before it installs anything, after checking
the new file with `visudo -c`. A box carrying an older or wider rule is tightened
on its next upgrade, and a hand-edited rule is put back.

## Explicitly Out of Scope

- Multi-tenant isolation
- Per-project credentials / RBAC
- Network policies between projects
- Per-user audit trails (there's one "who")

## Host Hardening

boxmunge hardens the VPS as part of installation:

- **UFW firewall** — deny all inbound except SSH, HTTP, HTTPS
- **CrowdSec** — community threat intelligence IPS
- **fail2ban** — brute-force protection
- **Kernel hardening** — sysctl overrides (SYN cookies, ASLR, restricted BPF, etc.)
- **AIDE** — file integrity monitoring on the control plane
- **Auditd** — kernel audit logging for privilege escalation and sensitive file changes
- **AppArmor** — tightened profiles for Caddy and system containers
- **Unattended upgrades** — automatic OS security patches
- **Automatic security and break-fix updates** — every 6 hours boxmunge checks for its own releases and applies security releases, plus break-fix releases unless `auto_update.breakfix` is `false`

## Per-Project Container Hardening

In addition to the host-level and platform-container hardening above, boxmunge applies a per-service hardening layer to every user project, silently and by default.

### What's applied (profile: `default`)

Every service in `compose.boxmunge.yml` receives:

- `security_opt: ["no-new-privileges:true"]` — blocks setuid / file-cap escalation inside the container.
- `init: true` — Tini for signal handling and zombie reaping.
- `pids_limit: 512` — kills fork bombs and exec storms.
- `cap_drop` of dangerous capabilities not in Docker's default deny set: `NET_ADMIN, SYS_PTRACE, SYS_MODULE, SYS_RAWIO, SYS_TIME, SYS_BOOT, MAC_ADMIN, MAC_OVERRIDE, MKNOD, AUDIT_WRITE, WAKE_ALARM, BLOCK_SUSPEND, LEASE, NET_RAW`.

These defaults are the **silent floor**. Existing v1 manifests need no edits — the v1→v2 migration adds nothing. The next deploy applies the protections automatically.

### How to relax a protection

Add a `security:` block to your `manifest.yml`. Project-level applies to all services; per-service overrides win.

Strongly preferred: keep `profile: default` and tweak only the field that needs relaxing.

```yaml
security:
  cap_add: [NET_RAW]      # re-add NET_RAW for ping/traceroute health checks
  pids_limit: 2048        # raise the process ceiling
```

Last-resort: turn the whole posture off for one service. Requires a non-empty `reason`. The reason is reproduced in deploy logs and `boxmunge security` output.

```yaml
services:
  web:
    security:
      profile: "off"
      reason: "deliberate honeypot service, see issue #42"
```

Quote `"off"`: PyYAML parses unquoted `off` as YAML 1.1 boolean `False`,
which the validator catches with a targeted error, but writing the quotes
in the first place avoids the round-trip.

A deploy-time `[WARNING] SECURITY OFF` message is emitted on every `stage`, `promote`, `deploy`, `prod-deploy`, `resume`, and `upgrade` for any service on `profile: off`. The warning is repeated by design — the shortest path to making it go away is removing `profile: off` from the manifest.

### Profile ladder

`off` → `default` → `strict` (Tier 3) → `paranoid` (Tier 8). `strict` and `paranoid` are reserved names; manifests using them today fail validation. They will arrive in future boxmunge releases with explicit migration guidance.

### Introspection

```text
boxmunge security <project>           # human-readable
boxmunge security <project> --json    # machine-readable (used by MCP)
boxmunge check <project>              # read-only health check, single project
boxmunge check-all --read-only        # read-only health check, every project
```

Shows the effective posture per service after profile + override resolution.

`boxmunge check-all` (without `--read-only`) is **state-mutating**: it
writes per-project health JSON, may call `compose_down` on critical
failures, and emits Pushover notifications. That form is what the systemd
health timer drives. Use `--read-only` for an introspection-only run that
prints the same report with no side effects.

## Security and Break-fix Releases

Every release has a class recorded in the version-check service's
`releases.json`: `security`, `breakfix` (a critical non-security fix), or
`feature`. Security releases are applied automatically within 12 hours.
Break-fix releases are applied the same way unless the box sets
`auto_update.breakfix: false` in `boxmunge.yml`. Feature releases are never
applied automatically. Automatic updates stay on the box's `major.minor`
line, and the version-check circuit breaker can hold a broken security or
break-fix release fleet-wide.

The class is decided from `releases.json` alone. The release workflow
refuses to build a tag that is not listed there with a valid class, writes
the matching `[security]` or `[breakfix]` marker into the GitHub release
title and notes (which boxes read when the version-check service is
unreachable), and publishes only after checking the release text classifies
exactly as `releases.json` says.

The `boxmunge upgrade` flow handles stashing, migration, and validation automatically. Release `SHA256SUMS` files are keyless-signed by the GitHub Actions release workflow (Sigstore Fulcio + Rekor), and the upgrade shim hard-requires a valid signature pinned to this repo's release workflow on a `vX.Y.Z` tag — an unsigned release is refused.

## Release trust chain (end-to-end)

A boxmunge release tarball travels from `git push` to a running box through
a chain of distinct trust links. Each link is pinned independently, so a
compromise of any single one cannot silently propagate.

1. **Source tree (`git` tag → repo state).** A `vX.Y.Z` tag pushed to
   `boxmunge/boxmunge` triggers `.github/workflows/release.yml`. The
   workflow checks out the tag's exact tree.

2. **CI workers (GitHub-hosted runners).** GitHub-managed compute. We
   accept the integrity of the runner pool as given — the trust-model
   note on supply-chain compromise of the platform release covers the
   downstream defence (signature verification on the box). The workflow
   runs as two jobs: a read-only `build` job (tests, installer, SBOM),
   which is where third-party packages are installed and run, and a
   `publish` job that alone holds the release-write and OIDC signing
   tokens and installs no Python packages. A dependency compromised in
   `build` therefore cannot sign or publish by itself, although it can
   still tamper with the files `build` hands to `publish`.

3. **GitHub Actions used by the workflow.** Every `uses:` in
   `release.yml` is pinned to a 40-character commit SHA, not a version
   tag, so a tag-takeover on (e.g.) `actions/checkout` cannot redirect
   to a malicious commit. Dependabot maintains these pins on a weekly
   schedule. A lint test (`tests/test_release_pinning.py`) refuses any
   workflow whose `uses:` references a tag.

4. **Python dependencies.** The workflow installs from hash-pinned
   `requirements.txt` files (generated by `pip-compile --generate-hashes`)
   with `pip install --require-hashes`. A package whose contents differ
   from the recorded SHA256 aborts the install. The same lint test
   refuses any release-workflow `pip install` line without
   `--require-hashes`.

5. **External binaries inside the system container.** age and rclone are
   downloaded over HTTPS in `system/Dockerfile`, then verified against
   `AGE_SHA256` and `RCLONE_SHA256` ARGs baked into the Dockerfile via
   `sha256sum -c`. Mismatched downloads abort the image build. Version
   and SHA bumps travel together through Dependabot or a single audit-
   visible commit.

6. **Base container images.** Every internal Dockerfile pins its base
   by digest (`FROM image:tag@sha256:<digest>`), not by tag, so a
   compromised tag pointer on Docker Hub cannot silently change what
   ships. Dependabot's docker ecosystem maintains these.

7. **SBOM generation.** `scripts/generate-sbom.sh` (called from the
   workflow) reads the installed environment and emits CycloneDX JSON.
   The SBOM enumerates exactly the versions verified in steps 4–6.

8. **Artifact signing.** The workflow calls `cosign sign-blob --yes` on
   `SHA256SUMS` (which itself covers the install script and every
   tarball) and on `boxmunge-install.sh`. Keyless signing produces a
   Fulcio certificate proving the signature was produced by this exact
   workflow on this exact tag, with the OIDC issuer being GitHub
   Actions. The signature is published as `SHA256SUMS.sig` +
   `SHA256SUMS.cert`. Signing has no fallback: if cosign cannot be
   installed or signing fails, the workflow fails and nothing is
   published.

9. **Release publication.** `softprops/action-gh-release` (SHA-pinned)
   attaches the install script, the tarball(s), `SHA256SUMS`, the
   cosign signature and cert, and the SBOM to a draft GitHub release
   (every file is required). The draft's title and notes are checked
   against the release's class in `releases.json`, then it is published.

10. **Download (on the operator's box).** `scripts/boxmunge-upgrade`
    downloads the bundle, `SHA256SUMS`, `SHA256SUMS.sig`, and
    `SHA256SUMS.cert` from the release URL.

11. **Signature verification.** Before running `sha256sum -c`, the
    upgrade shim verifies the cosign signature on `SHA256SUMS` against
    the pinned cert identity regex
    `^https://github\.com/boxmunge/boxmunge/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$`
    and the pinned OIDC issuer `https://token.actions.githubusercontent.com`.
    cosign is hard-required; an unsigned release is refused.

12. **Checksum verification.** The shim then runs `sha256sum -c` against
    the signed `SHA256SUMS` to confirm the tarball's contents.

13. **Installation.** Only after both signature and checksum verify does
    the shim extract and `pip install` the bundle into the standby
    venv.

A compromise of any single step is contained: a malicious Action
release does not pass step 3 (SHA pin); a poisoned PyPI mirror does not
pass step 4 (hash pin); a tampered upstream age binary does not pass
step 5 (SHA256 ARG); a hijacked Docker Hub tag does not pass step 6
(digest pin); a forged release does not pass step 11 (Fulcio identity
pin); a tampered bundle does not pass step 12 (signed checksum).

## CVE Policy as a Defensive Layer

boxmunge's CVE policy provides a defensive layer beyond container hardening. The policy treats unfixed upstream CVEs above the project's posture threshold as actionable: it quarantines projects automatically and surfaces operator-suppressible findings via the audit trail.

The trust-model assumptions for this layer are explicit:

- **Trivy's vulnerability database is correct.** False negatives in the DB pass through silently; false positives produce noise but never an unsafe outcome.
- **Suppressions are honest operator decisions.** A suppression is a signed-off declaration that a CVE has been reviewed and judged not exploitable in the deployed config. boxmunge does not second-guess it; the audit trail and the `until` date are the controls.
- **The operator is responsible for revisiting suppressions before they expire.** boxmunge enforces expiry mechanically (the finding becomes active again on the next scan after `until`) and emits a high-priority Pushover alert; what it cannot do is decide whether the CVE has actually been mitigated upstream or in the deployed code.

Like the rest of the trust model, this layer assumes a single trusted operator. There is no per-project review delegation and no multi-party approval for suppressions; the audit log is the only record of who signed off on what. See `agent-help cve` for the policy reference and `agent-help cve-incident` for the response playbook.
