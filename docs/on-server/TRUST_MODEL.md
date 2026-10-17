# boxmunge Trust Model

How boxmunge handles security boundaries, isolation, and access control.

---

## Threat Model

boxmunge's defences are calibrated against a specific set of attackers. Future evolutions may extend this scope; today, severity assessments assume the model below.

### In scope

- **Network-level third-party attackers** — scanning, brute-force SSH, DDoS, malicious traffic targeting the public surface. Mitigations: UFW, CrowdSec, fail2ban, kernel hardening, key-only SSH on a non-default port.
- **Supply-chain compromise of platform releases** — a tampered boxmunge release reaching the box. Mitigations: every release's `SHA256SUMS` is keyless-signed by the GitHub Actions release workflow (Sigstore Fulcio + Rekor), and the upgrade shim verifies the signature against a pinned workflow identity and OIDC issuer before installing. cosign is hard-required — an unsigned release is refused, not silently installed. This closes the prior circularity (where SHA256SUMS and the bundle came from the same release URL and could be replaced in lockstep).
- **Container-escape blast radius** — a compromised user container should not trivially own the host. Mitigations: per-service capability drops, `no-new-privileges`, `pids_limit`, Tini, the host-level platform-container hardening, and re-checking a project's files and mounts before every start (see "Container Escape and Root Restarts").

### Out of scope (current product)

- **Malicious operators** — whoever holds the `supervisor` key is root by design and fully trusted. The `deploy` key is trusted with every project on the box (single owner), not with the host: it reaches only the restricted shell, whose allowlist is all it can run (see "SSH access" below). A way for the deploy key to run anything else is a security bug.
- **Malicious agents / MCP tools** — at present, agents and tools invoked through the deploy shell or MCP are treated equivalently to operators. A future product evolution may split agent trust from operator trust; today they are the same principal. MCP and the shell do take the same privileged paths: MCP `upgrade` uses the shell's sudo route to the upgrade shim, and MCP `restore`/`rollback` require an explicit `confirm: true`.

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

**SSH access** is key-only for every account. boxmunge's sshd settings are in `/etc/ssh/sshd_config.d/00-boxmunge.conf`. That file sorts before every other drop-in, and sshd keeps the first value it reads, so a cloud image's `50-cloud-init.conf` saying `PasswordAuthentication yes` has no effect.
- Password, keyboard-interactive and root logins are off for everyone.
- X11, TCP and stream-local forwarding, agent forwarding and tunnels are off for everyone. A `Match User deploy` block keeps them off for deploy even if you open forwarding for supervisor in a Match block of your own.
- deploy accepts no client environment beyond `LANG`, `LC_*`, `COLORTERM` and `NO_COLOR`, and `~/.ssh/environment` and `~/.ssh/rc` are ignored. A variable such as `BASH_ENV` could otherwise run code before the shell does.

Every install, and every upgrade whose installer changed, rewrites the file. It then checks with `sshd -t` and `sshd -T` that sshd gives deploy and supervisor these settings. If sshd does not, the install puts the previous file back, leaves the running sshd alone and fails, naming what to change. An upgrade then stops before switching releases and blocklists that version: fix the setting, then `sudo /opt/boxmunge/bin/boxmunge-upgrade clear-blocklist <version>`. `health` reports the file as missing or changed (`sshd-hardening`). Run as root, it also reports a later sshd setting that widens what deploy accepts (`sshd-deploy-env`).

A second factor through keyboard-interactive (`AuthenticationMethods publickey,keyboard-interactive`, a TOTP PAM module for example) cannot be kept. With keyboard-interactive off, `sshd -t` refuses that configuration, so the install fails as above without locking anyone out. To keep two factors, use a FIDO2 security key (`ssh-keygen -t ed25519-sk`), which sshd treats as a public key. Then remove the `AuthenticationMethods` line and re-run the installer.

**Uploads** reach the box only through the restricted shell's `scp -t` path, which
files them into the inbox. SFTP is disabled for deploy: OpenSSH's sftp-server cannot
be confined to the inbox without chrooting every deploy session, and unconfined it
would give deploy read and write access to every file deploy can reach (secrets,
`backup.key`, `authorized_keys`, upgrade state) outside the shell's allowlist. Both
the shell and the `boxmunge-sftp` subsystem wrapper refuse it. Clients upload with
`scp -O`, the legacy protocol.

**Compose files** are confined to their own project. A project's `compose.yml` cannot set the compose project name, join or declare another project's networks (or `boxmunge-proxy`, so it cannot claim an alias there), use another project's named volumes, bind-mount or read files outside its own directory, or join another container's namespaces. See SECURITY.md, "What `compose.yml` may not do". A platform upgrade validates every project's compose file again with the new release's rules. The upgrade does not rebuild or restart a project whose file is now refused. The project keeps the overlay it had, the upgrade leaves its containers as they were, and the operator is alerted (OPERATIONS.md, "Upgrading the Platform"). That guarantee covers the upgrade alone, not other root-run operations such as container-update.

**Compose interpolation** sees only the project. Compose fills `${VAR}` from the project's own `.env` and from the environment of the process that runs it. boxmunge runs every docker command that touches project compose files (validation, `config`, `up`, `pull`, `build`, `down`, `exec`, `run`, backup and restore, staging copies), and its other docker calls too (the system container, health and doctor probes), with one fixed environment: `PATH` and `LANG=C.UTF-8`, nothing else, whoever started the command. Two docker-adjacent commands do not use it. One is install.sh, which runs `docker compose` for the platform's own Caddy and system stacks, files that ship with the release, as the admin running the installer. The other is `trivy`, which scans images from the daemon, never reads a compose file, and needs `HOME` for its cache. A deploy over SSH, a root systemd timer, `sudo` and MCP therefore resolve a compose file to exactly the model that was validated: a file cannot test for a variable such as systemd's `INVOCATION_ID`, or `COMPOSE_PROFILES`, to behave differently once a timer runs it. `${HOME}`, `${USER}` and every other caller variable are unset. Put project values in the project's `.env`.

**Logs and state** are per-project by default. The `boxmunge log` command scopes to a single project unless `--all` is passed. This prevents agent context pollution, not security isolation.

## What We Don't Isolate

- **Network** — every routed service (and Caddy) shares the `boxmunge-proxy` Docker network, so a routed container can open connections to another project's routed services on their ports. Services that are not routed (`internal: true`, or not in the manifest) sit only on their project's own networks. There is no network policy between routed services. Acceptable for single-owner.
- **Docker daemon, kernel, and host resources** — all projects run on one Docker daemon and one kernel; container hardening limits, but does not remove, what a compromised container can do to its neighbours (CPU, memory, and disk are shared unless `limits` are set).
- **Docker group** — the deploy user is in the `docker` group, which is effectively equivalent to root on the host (a user can mount the host filesystem via `docker run -v /:/host`). This is an intentional trade-off: the deploy user needs to run `docker compose` for deployments, and Docker's permission model requires group membership. Because of that, the restricted shell is the boundary for the deploy key: deploy's login shell is the restricted shell, sshd opens no channel that bypasses it, and the shell runs only its allowlist, in an environment it cleans first. Code that runs as the deploy user any other way, through a bug in an allowlisted command for example, is root.
- **Backup encryption key** — the deploy user can read the age identity key at `/opt/boxmunge/config/backup.key` (mode 640, group deploy). This is required for backup and restore operations to work without sudo. An authenticated deploy user can decrypt any backup snapshot.
- **Backups** — the deploy user can trigger backup/restore for any project.

## Container Escape and Root Restarts

A box installed from this release on is remapped from the first boot:
container uid N is host uid S+N, so container root is an unprivileged host
user (OPERATIONS.md, "User-namespace remapping"). A box installed earlier
runs without user-namespace remapping until it migrates, and the overlay
does not force a non-root user, so there uid 0 in a container is root for
every host file the container can reach through a bind mount. A compromised
container is therefore contained by what it can mount and by what root
later does with the files it can write.

Root does a lot with a project's files after deploy: upgrades restart every
project, container updates and `security resume` recreate them, and
`recover`, `resume`, `restore` and `stage` start them. Each of those runs
`docker compose up` (or `start`) on the files in the project directory, and
Docker resolves every bind source again, following symlinks, each time it
starts a container. Two escalations followed:

- **A container rewrites the files root starts it from.** A project could
  bind-mount its own directory read-write (`.:/app`), or compose.yml, the
  manifest, `.env`, the overlay or the kept releases. The container could
  then rewrite compose.yml to `privileged: true` with `/:/host`, and the
  next root restart ran it unvalidated.
- **A container redirects a bind mount.** A container that can write the
  directory holding another bind source can replace that source with a
  symlink to `/`; the next start mounts the host root.

What closes them:

- Compose validation refuses a read-write bind mount of the project
  directory or of anything boxmunge reads from it, and any bind source
  inside a read-write one (SECURITY.md, "Project isolation"). These are
  not relaxed by `profile: "off"`.
- Every start goes through one check (`boxmunge.compose_guard`), enforced
  by a test that no other code calls `compose up`/`start`. It re-runs
  deploy's own validation on the files on disk, then walks every bind
  source of the model it is about to run from the project directory
  without following symlinks: no path component may be a symlink, the
  source must exist inside the project, and it must still be the kind
  (directory or file) recorded when the project was deployed. Deploy and
  stage write that record (`state/deploy/<project>.binds.json`, outside
  the project) and create missing sources as plain directories, rather
  than leaving Docker to create them as root through whatever a symlink
  points at. An upgrade re-records each project from the configs it
  regenerates. The check also confirms every file boxmunge reads (the
  compose files, the manifest, `.env`, the generated overlay, and whatever
  `compose.yml` includes, extends or names in `env_file`/`label_file`)
  still hashes to what deploy recorded, so a container that rewrote a
  control file boxmunge's validator would still accept — a manifest set to
  `security.profile: off`, say — is refused until a redeploy re-blesses it.
  A project deployed before these rules, whose running container already
  mounts the project directory read-write, is caught by inspecting the
  live containers' own mounts and refused with "redeploy required". The
  validator also refuses a `provider:` service (Compose runs its type on
  the host) and validates every profile, not just the active ones. A
  staged release lives in its own tree (`.releases/staged/`), so the
  project directory stays production's; a staging start is checked against
  that tree and must mount nothing of production's. A project staged by
  boxmunge 0.10.1, which put the staged release's files in the project
  directory, has every production start refused until `legacy-stage`
  resolves it. While an install is open (`.releases/install.json`), only
  the install itself starts production. A start that fails the check
  does not happen: it is logged, alerted at high priority, and the
  running containers are left as they are.

What remains:

- Docker itself restarts containers (restart policies, a daemon restart,
  a reboot) without any boxmunge check. With no bind source inside a
  read-write one, a container cannot redirect its own mounts, but the
  check cannot cover those starts.
- The check and Docker's mount are separate steps, so there is a short
  window between them.
- Anything a container can do as root inside its own read-write mounts
  stays possible, and so does a kernel or runtime escape.

Recommended follow-ups, not implemented: migrate boxes installed before
`userns-remap` was the default, so container root maps to an unprivileged
host uid there too, and give the overlay a default non-root user.

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
  upgrade deletes. The one exception is an upgrade or rollback killed
  mid-swap, proven by a root-owned `upgrade-inflight` or `rollback-inflight`
  marker in a venv slot: the shim then follows `env-active` and rewrites
  `active-slot`.
- `probation.json` must be a JSON object with a semver `version`, an
  ISO-8601 `expires_at` with a timezone, and a `previous_slot` of `a` or `b`
  that is the current standby slot and a working venv (promotion deletes
  it; a rollback swaps to it). One naming the live slot is stale and is
  removed. An `expires_at` later than a fresh probation's 6 hours (plus 15
  minutes for clock steps) counts as expired, so a forged far-future value
  cannot hold off upgrades.
- `blocklist.json` must be a JSON object keyed by semver versions.
- None of these files, nor the legacy `upgrade.lock` (below), may be a
  symlink, a FIFO or anything but a plain file. Root opens them without
  following a link or blocking (bash never opens a lock by name: Python opens
  it and hands the shim the descriptor), and writes them by rename from a temp
  file it wrote through its own descriptor, so a planted link is replaced, not
  followed.
- The shim runs from `/` with `PYTHONSAFEPATH=1`, so a module planted in the
  caller's working directory is never imported as root.

Any violation stops the shim with a non-zero exit and an error naming the
file, before the value reaches a path, a URL, or an `rm -rf`. Repair or remove
the file as `supervisor` and re-run.

The shim deletes a venv slot only while the live one runs, and never the live
one. State deploy must not influence is root-only: the crash-safety markers
inside the venv slots, and the interruption counts and `upgrade.lock` in
`/opt/boxmunge/upgrade-root/` (root, 0700). One upgrade runs at a time because
the shim, `auto-update`, `check-probation` and `legacy-stage` all hold that
lock, which deploy cannot replace. Shims up to 0.10.1 locked
`upgrade-state/upgrade.lock` instead, and the one that installs this release
keeps running until its upgrade ends, so every taker locks that file too (after
the root-only one). Deploy can still swap that legacy file, which matters only
while a 0.10.1 shim or venv is running; it goes once no box can run one.

### Files root writes in deploy-writable directories

`logs/`, `state/`, `stashes/`, `inbox/` and project trees are writable by deploy, and root
writes there too (timers, upgrades). Root opens those files without following a final-component
symlink and refuses anything but a plain file with one link (the operational log, lock files,
the container-update lock, stash archives, decrypted restore snapshots). It sets owner and mode
on the open descriptor, never by name after the fact (atomic state writes, backup dumps and
temps). A planted link makes the operation fail with an error naming the path, instead of
redirecting root to another file. Remove the link and re-run.

This protects the last path component only. Deploy can still swap an intermediate directory it
owns (`projects/<p>/backups`, a `state/` subdirectory, `inbox/.tmp`) for a symlink, so a root
write below it can land elsewhere. Deploy is root-equivalent through the docker group anyway;
these checks are defence in depth, not a boundary.

Only the deploy uid can write `projects/`, `projects/<p>/` and `<p>/.releases/` (all
deploy:deploy 0755). That includes project code that runs on the host as deploy (the
`pre_deploy` hook and what it launches) and the boxmunge-system container (deploy uid). No
service, staging, build or data-helper container can, and no smoke script can. Read-write binds
may not be the project directory, a control entry or `.releases`, and remapped container uids
are "other" on those 0755 directories. So root operations that walk these paths by name
(`legacy-stage` restore and chown, `install_release` when root runs it, slot teardown, stash
restore, project-delete under sudo) are protected against a planted final component, but not
against a parent swapped by deploy. That is acceptable because deploy is root-equivalent. It
becomes a boundary if deploy ever loses docker access, or if agent trust is split from operator
trust. Those operations then need dir-fd traversal.

Project code never runs on the host as root. An operator who runs `prod-deploy`, `rollback` or
`promote` with sudo makes boxmunge root, and the `pre_deploy` hook still runs as deploy: root
switches to deploy's uid, gid and groups for it, with the deploy shell's environment, no stdin,
its own session (no terminal of root's to push input into) and no other inherited descriptor.
A deploy interrupted while its hook runs (Ctrl-C, an error) kills the hook's whole process group,
so nothing the hook started outlives the deploy.
On a host with no deploy user the hook is not run and the deploy fails, saying so.

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
- **CrowdSec** — community threat intelligence IPS. It reads Caddy's access log from the
  container's stdout through the Docker API, never from a file: a file would sit in a
  directory Caddy (remapped, so it owns that directory) controls, and root CrowdSec would
  open whatever Caddy put there (a FIFO, `/dev/zero`, a link to a root-only file). Caddy
  logs no request or response headers or TLS details and cuts every client-set field to a fixed length, so no
  request makes a line long enough to stop CrowdSec's tail. Its
  unit runs with `MemoryMax=512M`, `TasksMax=256` and `Restart=on-failure`
  (`crowdsec.service.d/boxmunge-limits.conf`), so a flood can neither exhaust the host's
  memory nor switch detection off for good
- **fail2ban** — brute-force protection
- **Kernel hardening** — sysctl overrides (SYN cookies, ASLR, restricted BPF, etc.)
- **AIDE** — file integrity monitoring on the control plane
- **Auditd** — kernel audit logging for privilege escalation and sensitive file changes
- **AppArmor** — tightened profiles for Caddy and system containers
- **Unattended upgrades** — automatic OS security patches. `health` (`auto-updates`) and every
  `auto-update` run check that package lists are refreshing and updates are being installed,
  and `auto-update` alerts when they are not
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
applied automatically. Each release is also marked `breaking` or not.
Automatic updates may move a box to a newer minor line, but only when no
release between the box's version and the candidate (the candidate
included) is breaking, and never into a new major version. A box that
cannot reach a security or break-fix release for that reason alerts its
operator and reports a `platform-updates` health warning instead. The
version-check circuit breaker can hold a broken security or break-fix
release fleet-wide.

The class and the breaking flag are decided from `releases.json` alone. The
release workflow refuses to build a tag that is not listed there with a
valid class and breaking flag, or a breaking release that is not `X.Y.0`,
writes the matching `[security]` or `[breakfix]` marker, and `[breaking]`
for a breaking release, into the GitHub release title and notes (which boxes
read when the version-check service is unreachable), and publishes only
after checking the release text carries exactly the markers `releases.json`
calls for.

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
    the shim extract the bundle and install it into the standby venv.
    Dependencies come only from the hash-pinned `requirements-build.txt`,
    `requirements-tui.txt` and `requirements-mcp.txt` inside the bundle
    (so covered by the signed `SHA256SUMS`), installed with
    `pip install --require-hashes`;
    the package itself is installed with `--no-deps --no-build-isolation`,
    so pip resolves and downloads nothing else. The venv's pip is not
    self-upgraded. `install.sh` installs the same way. A bundle without
    the pinned requirements files is refused.

A compromise of any single step is contained: a malicious Action
release does not pass step 3 (SHA pin); a poisoned PyPI mirror does not
pass step 4 (hash pin); a tampered upstream age binary does not pass
step 5 (SHA256 ARG); a hijacked Docker Hub tag does not pass step 6
(digest pin); a forged release does not pass step 11 (Fulcio identity
pin); a tampered bundle does not pass step 12 (signed checksum);
a poisoned PyPI package does not pass step 13 on the box either (hash pin).

## CVE Policy as a Defensive Layer

boxmunge's CVE policy provides a defensive layer beyond container hardening. The policy treats unfixed upstream CVEs above the project's posture threshold as actionable: it quarantines projects automatically and surfaces operator-suppressible findings via the audit trail.

The trust-model assumptions for this layer are explicit:

- **Trivy's vulnerability database is correct.** False negatives in the DB pass through silently; false positives produce noise but never an unsafe outcome.
- **Suppressions are honest operator decisions.** A suppression is a signed-off declaration that a CVE has been reviewed and judged not exploitable in the deployed config. boxmunge does not second-guess it; the audit trail and the `until` date are the controls.
- **The operator is responsible for revisiting suppressions before they expire.** boxmunge enforces expiry mechanically (the finding becomes active again on the next scan after `until`) and emits a high-priority Pushover alert; what it cannot do is decide whether the CVE has actually been mitigated upstream or in the deployed code.

Like the rest of the trust model, this layer assumes a single trusted operator. There is no per-project review delegation and no multi-party approval for suppressions; the audit log is the only record of who signed off on what. See `agent-help cve` for the policy reference and `agent-help cve-incident` for the response playbook.
