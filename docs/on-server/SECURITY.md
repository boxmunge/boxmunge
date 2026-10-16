# boxmunge Container Security Model

Per-project container hardening — what protects you by default, how to relax it
when you must, and what's coming in future tiers.

## TL;DR for agents

- **Defaults are silent.** Every service deployed via boxmunge runs with
  `no-new-privileges`, Tini init, a 512-process ceiling, and a list of
  dangerous Linux capabilities dropped. That includes services that appear
  only in `compose.yml` (databases, caches, sidecars). Services declared in
  the manifest also get a read-only root filesystem; undeclared ones do not
  yet, and every deploy, stage, and validate warns about each of them. You do
  nothing to get this.
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
read_only: true             # v0.8
tmpfs: ["/tmp"]              # v0.8
```

These caps are NOT in Docker's default deny list, but are dangerous and rarely needed by application code. `NET_RAW` is the only borderline drop — it powers `ping`, `traceroute`, and a few health-check scripts. If your app actually needs it, opt back in via `cap_add`.

### v0.8 read-only rootfs default

`read_only: true` and `tmpfs: ['/tmp']` were added to the default profile in v0.8. The CVE policy already treated missing `read_only` as a +1 hardening penalty; v0.8 closes the asymmetry by actually enforcing read-only rootfs at runtime so the platform delivers what it penalises operators for omitting.

**User-wins on explicit declarations.** If your `compose.yml` declares `read_only` (true or false) on a service, the overlay omits its own `read_only` entry for that service. Compose merge then leaves your literal value alone — there's no merge conflict and no redundancy-rejection rule. The same rule applies to `tmpfs: ['/tmp']`: if you declare a `tmpfs` or `volumes` entry that targets `/tmp`, the overlay omits its `tmpfs` entry for that service.

**Services that are not in the manifest.** A service that exists only in
`compose.yml` (typically a database or cache) gets `no-new-privileges`, init,
the process limit, and the capability drops, resolved against the
project-level `security:` block (a project-level `profile: "off"` covers it
too). It does **not** get `read_only: true` or the `/tmp` tmpfs yet: a platform
upgrade regenerates every overlay, so turning read-only on for these services
would break existing databases across the fleet at the next upgrade. Every
`deploy`, `stage`, and `validate` prints a `[WARNING]` naming each undeclared
service. A future release will make a read-only root filesystem the default for
undeclared services too, so opt in now.

To opt in, declare the service in the manifest. A service with `internal: true`
needs no `port` or `routes`; give it a `writable:` block. Use `ephemeral:` for
the paths it writes if it keeps no data in `compose.yml` volumes. For a
database whose data already lives in a `compose.yml` volume, use
`external: true` and list the paths it writes as `tmpfs:` in `compose.yml`
(this keeps the existing volume and its data):

```yaml
# manifest.yml
services:
  db:
    internal: true
    writable:
      external: true
```

```yaml
# compose.yml
services:
  db:
    image: postgres:16-alpine
    tmpfs: [/tmp, /var/run/postgresql]
    volumes: [pgdata:/var/lib/postgresql/data]
```

A declared service is treated like any manifest service: it also receives the
project's `env_files` and `secrets.env`.

**Opting out.** Apps that legitimately need writable rootfs declare `read_only: false` in `compose.yml` and accept the +1 CVE hardening penalty consciously. Most apps just need `tmpfs:['/tmp']` (the v0.8 default) and possibly extra tmpfs entries for cache/log paths under read-only rootfs.

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

## What `compose.yml` may not do

Your `compose.yml` is merged with the generated overlay, and Compose lets some
user keys win over it. So every deploy, stage, resume, and upgrade checks
`compose.yml` first and refuses to proceed (exit code 3) when it finds a key
that would undo the hardening. Values are normalised before they are compared:
letter case, surrounding spaces, a `CAP_` prefix, and `=` versus `:` in
`security_opt` make no difference.

The checks run on the configuration Compose will actually start: the output of
`docker compose -p <project> config`, with `${VAR}` interpolated from the
project's `.env` and the environment, and `extends:` and `include:` files
merged in. A value hidden behind a variable or in an included file is checked
like any other.

| Rejected | Why |
|---|---|
| `privileged: true` | Full host access. |
| `privileged`, `read_only`, or `init` given as anything but an unquoted `true`/`false` | A quoted `"true"` is not checked as a boolean. Write the bare value. |
| `pid`, `ipc`, `network_mode`, `uts`, `userns_mode`, `cgroup` set to `host` | Shares a host namespace. |
| `use_api_socket: true` | Hands the container the Docker daemon's API, which can start privileged containers with any host path mounted. Remove it. |
| `privileged` on a `post_start` or `pre_stop` hook, or on a `develop.watch` `exec` hook | The hook regains every capability the hardening drops. Remove `privileged:`; hooks run with the service's own privileges. |
| `cap_add` of a denied capability | See the denylist below. |
| `security_opt` with `unconfined`, `label:disable`, `no-new-privileges:false`, or a custom `seccomp` profile file | Disables a kernel confinement layer. `seccomp=runtime/default` is fine. |
| `devices`, `device_cgroup_rules`, `gpus`, `deploy.resources.reservations.devices` | Exposes host devices. |
| `cgroup_parent` that is absolute or contains `..` | Escapes the container cgroup. |
| A bind mount of a protected host path, anything inside one, or any parent of one | Protected: the Docker and containerd sockets and state, `/proc`, `/sys`, `/dev`, `/etc`, `/boot`, `/root`, `/home`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, and the boxmunge root outside `projects/`. Paths are compared after `~` expansion, joining relative paths to the project directory, collapsing `..` and `//`, and resolving symlinks, so `/run` (the parent of `/run/docker.sock`), `/tmp/../etc`, and `../../config` are all refused. |
| `${VAR}` or `$VAR` inside a bind-mount source | The path cannot be verified. Write it literally. |
| A bind mount outside the project directory | One project must not read or write another's files. Use paths such as `./data`; an absolute path is fine if it is inside `/opt/boxmunge/projects/<project>/`. Symlinks are resolved before the check. |
| `build.network: host`, `build.privileged`, `build.entitlements` | Build steps run in a container too; keep them off the host network and unprivileged. |
| A long-syntax mount of `type: npipe` or `type: cluster` | Its source cannot be checked. Use `bind` (inside the project), `volume`, `tmpfs` or `image`. |

### Capability denylist

These capabilities let a container reach the host, so neither `compose.yml`
`cap_add` nor the manifest's `security.cap_add` may grant them under the
default profile: `ALL`, `SYS_ADMIN`, `DAC_READ_SEARCH`, `BPF`, `PERFMON`,
`SYS_RESOURCE`, `SYS_MODULE`, `SYS_RAWIO`, `SYS_BOOT`, `MAC_ADMIN`,
`MAC_OVERRIDE`. A service that truly needs one must use `profile: "off"` with a
reason. Capabilities that are dropped by default but have real uses
(`NET_RAW`, `NET_ADMIN`, `SYS_PTRACE`, and the rest of the default `cap_drop`
list) can be added back. In the manifest, write capability names in canonical
form: upper case, no `CAP_` prefix (`NET_RAW`, not `cap_net_raw`).

Services on `profile: "off"` get a logged warning for each of these instead
of a rejection.

### Project isolation

These rules keep one project's `compose.yml` from reaching another project.
They apply to every service and are **not** relaxed by `profile: "off"`.

| Rejected | What to do instead |
|---|---|
| A top-level `name:` | Remove it. boxmunge runs every compose command as `-p <project>` (`-p <project>-staging` for staging). |
| An `external: true` network, including `boxmunge-proxy` | Remove it. boxmunge attaches routed services to `boxmunge-proxy` itself; declare only the project's own networks. |
| A top-level network or volume with a `name:` other than Compose's default (`<project>_<key>`) | Remove the `name:` line. |
| A network with a `driver` other than `bridge` (`macvlan`, `ipvlan`, ...) | Remove the `driver:` line. |
| A service joining a network the file does not declare | Declare it, or use `default`. Any alias is fine on the project's own networks; they cannot collide with another project's. |
| An `external: true` volume, or a volume with `driver`/`driver_opts` | Use a plain named volume (`data: {}`) or a bind mount inside the project. |
| `external_links`, or `volumes_from: [container:<name>]` | Reach services in the same file by service name; name a service in `volumes_from`. |
| A `secrets`/`configs` `file:` outside the project directory | Keep the file inside the project. Secret values belong in `secrets set`. |
| A build input outside the project: the `build` context, any `build.additional_contexts` path, or the `build.dockerfile` (resolved against the context, symlinks followed) | Keep every build input inside the project. Remote git or HTTP(S) contexts, and `docker-image://<image>` or `service:<name>` additional contexts, are fine. |
| Any other build context form (`oci-layout://`, `file://`, ...), `build.ssh`, a `type=local` (or other non-registry, non-inline) `build.cache_from`/`cache_to`, a `build.network` naming a Docker network, or a build key boxmunge does not know | These read host files or credentials, or reach another project's network. Vendor private dependencies into the project, use `type=registry` or `type=inline` caches, and leave `build.network` unset or `none`. |
| `network_mode` other than `none`, `host` (a hardening rule above) or `service:<name>`; `pid` or `ipc` set to `container:<name>` (or anything but `service:<name>`, `host`, and for `ipc` `none`/`private`/`shareable`) | Joins a Docker network or another container's namespace by name, which may be another project's (`bridge` included). Use the project's own networks, or `service:<name>` for a service in the same file. |
| A build whose image name (`image:`, or Compose's default `<project>-<service>`) or any `build.tags` entry is outside the project's image namespace | Image names are shared by every project and the platform, so a build could replace another project's image or a public one they run. Name built images `<project>-<name>`, `<project>_<name>` or `<project>/<name>`, with no registry host. Hyphenated project names overlap (`foo-bar-web` is in `foo` and `foo-bar`): a name belongs to the longest project name it starts with. |
| An `image:` (on a service without `build`) in another project's image namespace | Compose would run that project's locally built image without pulling. Use a published image from a registry, or build your own. |
| `provider:` on a service, or `models:` (top-level or on a service) | These hand the service to something outside its containers; a provider is an executable run on the host as whoever deploys. Run the service from an image. |
| `ports:` on any service | Remove it: routed traffic reaches the service through Caddy. A port that must be published goes in the manifest, below. |
| An `include:`, `extends: file:`, `env_file:`, or `label_file:` path outside the project directory (followed through nested includes), remote, or written with `${VAR}` | Keep every compose, extends, include, env and label file inside the project, and write the path literally. |

### Published ports (opt-in)

All ingress is meant to go through Caddy. Docker publishes `ports:` with its own
firewall rules, so a published port bypasses UFW and the CrowdSec bouncer. That
is why `compose.yml` may not contain `ports:`. When a port really must be
reachable from the host (an admin tool reached over an SSH tunnel, say),
declare it at the manifest's top level, with a reason:

```yaml
security:
  published_ports:
    - service: db              # any service in compose.yml
      port: 5432               # container port
      reason: "pgAdmin over an SSH tunnel"
      # host_port: 15432       # defaults to port
      # protocol: udp          # defaults to tcp
      # host_ip: 0.0.0.0       # explicit widening; defaults to 127.0.0.1
```

boxmunge publishes the port in the generated overlay, bound to `127.0.0.1`
unless `host_ip` says otherwise, and prints a `[WARNING]` naming the port and
the reason on every deploy. A `host_ip` other than loopback makes the port
reachable from the network with no UFW or CrowdSec protection, and the warning
says so. Staging never publishes ports, so it cannot collide with production.

## Wildcard hosts and routing isolation

boxmunge rejects wildcard host entries (e.g. `*.example.com`) by default. On a single Caddy instance shared between projects, a wildcard on one project can capture traffic intended for adjacent projects whose plain hostnames happen to fall under that wildcard. boxmunge runs single-tenant — every project on a host is owned by the same operator — so this is a footgun, not a multi-tenant breach. We still gate it behind an explicit opt-in:

```yaml
allow_wildcard_hosts: true
hosts:
  - "*.example.com"
```

Without `allow_wildcard_hosts: true`, manifest validation refuses to deploy. With it set, you accept that any plain `foo.example.com` belonging to another project on the same host is at risk of being shadowed by the wildcard's routes. Don't enable it on a host where you intend to operate adjacent projects under the same parent domain.

## What is NOT applied by default (and why)

| Not applied | Reason | When |
|---|---|---|
| Non-root user enforcement | Many container images run as root. | Tier 3 (`strict`). |
| `cap_drop: ALL` | We drop only the dangerous subset. Full drop breaks several apps. | Tier 3 (`strict`). |
| Default memory/CPU caps | Existing `limits` field is the user's tool. | Never imposed by default. |
| Egress allowlist | Default-deny outbound needs network design. | Tier 4. |
| Custom seccomp profile | Docker's default seccomp already applies. | Tier 8 (`paranoid`). |
| Image scanning, digest pinning | Detection-without-remediation is a UX trap. | Tier 2 (v0.6) with auto-remediation pipeline. |

(`read_only: true` rootfs was on this list through v0.7; v0.8 promoted it to a default-profile baseline. See "What `default` applies" above.)

See `agent-help architecture` and the on-server `TRUST_MODEL.md` for adjacent context (host hardening, restricted shell, platform container hardening).

## CVE policy

Container hardening is one half of the protection model — the other is responding when a CVE is published against an image you're running. boxmunge v0.6.0+ scans deployed images daily via Trivy and automatically quarantines projects when an unfixed CVE crosses the project's configured posture threshold.

See [CVE_POLICY.md](CVE_POLICY.md) for posture tiers, the suppression workflow, and the recovery flow after a quarantine.

## Supply-chain protection (release signing)

Every boxmunge release tarball's `SHA256SUMS` is keyless-signed by the GitHub Actions release workflow using Sigstore (Fulcio + Rekor). The upgrade shim verifies that signature against a pinned certificate identity (the release workflow on a `vX.Y.Z` tag of this exact repo, issued by GitHub's OIDC) BEFORE running `sha256sum -c`. cosign is hard-required: if it's missing, the upgrade aborts noisily rather than degrading to checksum-only. This breaks the circularity of "verify the tarball with a hash file pulled from the same release" — an attacker who replaces both files in lockstep can no longer pass verification without also forging a Fulcio certificate tying the signature to this repo's release workflow. An unsigned release (e.g. one where the cosign install step in CI failed) will be refused by the shim, not silently installed.
