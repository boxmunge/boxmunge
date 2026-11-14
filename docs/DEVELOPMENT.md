# Developing boxmunge

A map of the codebase for contributors: what lives where, how a command flows, how to test it, and
how a release reaches a server. Read [CONTRIBUTING.md](../CONTRIBUTING.md) first for the principles
every change is held to.

## Two packages, one repository

| Package | Directory | Distributed as | Runs on |
|---|---|---|---|
| `boxmunge-server` | `src/boxmunge/` | Signed GitHub releases, installed and upgraded by `scripts/boxmunge-upgrade` | The VPS |
| `boxmunge` (client) | `cli/` | PyPI | A developer's machine |

The client bundles a project, uploads it, and drives the server over SSH. It never touches the
server's filesystem directly. The two version independently: server releases are tagged `v*`, client
releases `cli-v*`. Compatibility is negotiated by `handshake` (server version, minimum client
version, manifest schema version).

## Repository layout

```text
src/boxmunge/            server package
  cli.py                 command registry (COMMANDS) and dispatch
  shell.py               restricted deploy shell (ALLOWED_COMMANDS)
  commands/              one module per command: cmd_<name>(args) plus run_<name>(...)
  cve/                   CVE scanning, the trust-ladder policy engine, KEV feed, quarantine
  health_checks/         checks used by health and check-all
  tui/                   the `console` terminal UI
  api/                   the action registry and boxmunge-apid, the plugin API daemon (dev mode
                         only so far; see docs/PLUGIN_API.md)
  mcp_server.py          MCP tool registry (_TOOL_DEFS); mcp_tools.py holds the handlers
  paths.py               every on-box path, derived from one root (BoxPaths)
  manifest.py            manifest loading and validation; migration.py upgrades old schemas
  compose.py             generates the compose overlay (networking, env, limits)
  security_overlay.py    per-service container hardening
  compose_validate.py    rejects unsafe user compose files, checked on the resolved model from
                         compose_resolve.py; rules in compose_service_rules.py,
                         compose_mounts.py, compose_isolation.py; capability denylist in
                         capabilities.py
  caddy.py               generates per-project Caddy site config
  backup.py              age encryption, run inside the system container
  fileutil.py            atomic writes and the advisory locks every mutation uses
cli/src/boxmunge_cli/    client package
bootstrap/init-host.sh   one-time host provisioning (users, sshd, UFW, Docker, Caddy)
install.sh               lays down /opt/boxmunge from a release bundle
scripts/boxmunge-upgrade the root upgrade shim: download, verify signature, swap venvs, probation
system/                  the boxmunge-system container (age, rclone)
systemd/                 timers: backup, backup-sync, health, cve-scan, container-update, auto-update
canary/                  the project self-test deploys to prove the pipeline works
docs/on-server/          operator and agent docs, shipped to the box and served by agent-help
services/version-check/  the public update-discovery service (itself deployed as a boxmunge project)
upgrade-notes/           what each release asks of projects and boxes (see "Upgrade notes")
tests/                   server tests; tests/integration/ uses real Docker; tests/vm/ boots a VM
```

## How a command works

Every server command is a module in `src/boxmunge/commands/`. The usual shape is:

- `cmd_<name>(args: list[str]) -> None` parses arguments, calls the inner function, and exits with
  its return code.
- `run_<name>(project, paths, ...) -> int` does the work and returns `0` on success, `1` on
  failure, or `2` for a usage error or critical, unrecoverable state.

`cli.py` maps command names to `cmd_*` handlers. The deploy user reaches them through `shell.py`,
which only runs names in `ALLOWED_COMMANDS` and starts each as a `boxmunge-server` subprocess.
The MCP server exposes a subset as tools.

**This is changing.** A single action registry with typed results and capability tiers
(`src/boxmunge/api/`) is meant to become the one definition the CLI, shell, MCP, and plugins derive
from. Today only `boxmunge-apid` serves it, in dev mode against a fixture box; the CLI, shell and
MCP still keep their own tables, so adding a command means touching several places, listed below.

### Adding a command today

1. Create `src/boxmunge/commands/<name>_cmd.py` with `cmd_<name>` and `run_<name>`. Parse
   arguments in `cmd_<name>` with `boxmunge.commands.argv.parse_args`, which rejects any flag or
   positional the command does not declare (exit 2). Never ignore an argument, and never accept
   `--dry-run` unless the command implements it. `cli.main` handles `-h`/`--help` for you.
2. Register it in `COMMANDS` in `src/boxmunge/cli.py`.
3. Decide whether the deploy user may run it. Either add it to `ALLOWED_COMMANDS` in
   `src/boxmunge/shell.py`, or add it to `INTENTIONALLY_RESTRICTED` in `tests/test_shell.py` with
   a comment saying why. A test fails until you choose.
4. If agents should call it over MCP, add a tool to `_TOOL_DEFS` in `src/boxmunge/mcp_server.py`
   and a handler in `src/boxmunge/mcp_tools.py`.
5. Add it to `HELP_TEXT` in `src/boxmunge/commands/help.py` (in the operator section if the
   deploy shell does not allow it), give it a usage entry in `USAGE` in
   `src/boxmunge/commands/usage.py` (what `help <command>` prints), and document it in
   `docs/on-server/OPERATIONS.md`. Tests fail until every registered command has a usage entry
   and a line in `help`.
6. If it only reads state, give it `--json`.
7. Validate every project name with `boxmunge.paths.validate_project_name` before use.
   `BoxPaths` also validates names when it builds a project path, so an invalid name raises rather
   than resolving outside the project.

### Rules that matter on a shared box

- **Lock before you mutate.** Per-project changes take the project lock (`fileutil`), Caddy reloads
  take the Caddy lock, registry changes take the registry lock. The health check runs every five
  minutes as root, and the container-update and CVE-scan timers also run as root, so unlocked
  writers race with them.
- **Write state atomically** with `fileutil.atomic_write_text` or `state.write_state`.
- **Mind file ownership.** Some code runs as root (timers, the upgrade shim) and some as `deploy`.
  A file root creates under a deploy-owned directory can become unreadable to `deploy` or to the
  system container, which runs as the deploy user's uid:gid (the owner of `projects/`). Give files
  that age or rclone touch to that user with `backup.chown_for_system_container`.
- **age and rclone run in a container, with no host fallback.** Get a handle with
  `system_container.connect(paths)` and pass every path through `tools.path()`. Paths must be
  under a mount of `boxmunge-system` (`projects/`, the backup key, `config/rclone/`), not `/tmp`;
  anything else raises before the tool runs.

## Where state lives on a server

| Path | Owner | Contents |
|---|---|---|
| `/opt/boxmunge/config/` | root:deploy | `boxmunge.yml`, backup key, host secrets, suppressions |
| `/opt/boxmunge/projects/<p>/` | deploy | manifest, compose files, generated overlay, secrets, backups, data |
| `/opt/boxmunge/inbox/` | deploy | uploaded bundles waiting for `stage` or `prod-deploy` |
| `/opt/boxmunge/state/` | deploy | registry, locks, health, deploy, staging, scan, KEV, container-update, platform-update and OS-update state, and the unconfigured-alerts log throttle |
| `/opt/boxmunge/upgrade-state/` | root:deploy | active venv slot, probation, blocklist |
| `/opt/boxmunge/logs/boxmunge.log` | deploy, group-writable | structured JSON-lines operational log, written by root and deploy |
| `/opt/boxmunge/caddy/` | root:deploy | Caddyfile and generated `sites/*.conf` |

`src/boxmunge/paths.py` is the source of truth for every path.

## Reader and lock inventory

The `deploy` user can put anything at a name under `state/`, `projects/<p>/`, `inbox/` or
`upgrade-state/`: a symlink to a file elsewhere, a link to nothing, a FIFO, a huge file. Root reads
those names from timers (health, scan, auto-update), so every such read goes through
`fs_nofollow`, and every lock file keeps one identity for as long as anything might hold it.

### Readers

`read_text_nofollow_or_none`, `read_text_nofollow` and `read_bytes_nofollow` open without following
a link, never wait on a FIFO, and refuse a file past their cap. Only "nothing at the name" reads as
no record: use `read_text_nofollow_or_none` for that, never `Path.exists()`, which follows a link.
Most JSON state is read through `state.read_state`, which wraps the helper; its callers aren't
listed.

Everything in the first table is deploy-writable. The cap is `fs_nofollow.READ_LIMIT_BYTES`
(64 MiB) unless a row says otherwise.

| Module | Functions | Reads | Under |
|---|---|---|---|
| `state.py` | `read_state` | any JSON state record its callers name (deploy, health, paused and more) | `state/` |
| `project_registry.py` | `_read_text` | `projects.txt`, the registry. Cap: 1 MiB (`REGISTRY_LIMIT_BYTES`) | `state/` |
| `blocked_update.py` | `read_blocked_state` | `platform-updates.json` | `state/` |
| `os_update_alert.py` | `read_os_update_state` | `os-updates.json` | `state/` |
| `manual_update.py` | `read_manual` | `platform-manual-update.json` | `state/` |
| `discovery_freshness.py` | `_read` | `update-discovery.json` | `state/` |
| `notify.py` | `_unconfigured_logged_recently` | `alerts-unconfigured.json` | `state/` |
| `project_alerts.py` | `_already_alerted` | a project's alert throttle | `state/` |
| `start_alerts.py` | `alerted_recently`, `record` | `start-refused/<p>.json` | `state/` |
| `container_update_targets.py` | `read_target_state` | `container-updates/<target>.json` | `state/` |
| `health_checks/container_updates.py` | `check_container_updates` | the same, for the health check | `state/` |
| `cve/breaker.py` | `read_held`, `alert_pending` | `cve-breaker.json` | `state/` |
| `cve/kev.py` | `load_kev` | `kev/catalog.json` | `state/` |
| `cve/kev_withdrawals.py` | `_entries` | `kev/withdrawn.json` | `state/` |
| `cve/kev_source_history.py` | `_entries` | `kev/sources.json` | `state/` |
| `cve/quarantine.py` | `read_quarantine_state` | `deploy/<p>.quarantined.json` | `state/` |
| `cve/scan_state.py` | `scan_problem` | `scans/<p>.json` | `state/` |
| `bind_sources.py` | `_load_record` | a project's bind-source record | `state/` |
| `run_as.py` | `read_users` | a project's users record | `state/` |
| `user_drift.py` | `held_back` | a project's user-drift record | `state/` |
| `cve/suppressions.py` | `load_suppressions`, `_load_history` | `security/suppressions.yml` and its history | `projects/<p>/` (the host's list is in `config/`) |
| `release.py` | `_read_meta` | `.releases/live.json`, `previous.json` | `projects/<p>/` |
| `release_keep.py` | `_reads_as` | `.releases/previous.json`, compared before it is rewritten | `projects/<p>/` |
| `release_txn.py` | `load_txn`, `_sha` | `.releases/install.json` | `projects/<p>/` |
| `staged_release.py` | `load_slot` | the staging slot's `meta.json` | `projects/<p>/` |
| `data_dirs.py` | `_load_record` | `.releases/data-dirs.json` | `projects/<p>/` |
| `unresolved_stage.py` | `_state_active`, `_records` | a stage state file from 0.10.1 or earlier, `legacy-stages.json` | `state/` |
| `compose_up_steps.py` | `restore_build_names` | the generated compose overlay | `projects/<p>/` |
| `overlay_users.py` | `_overlay_users` | the generated compose overlay | `projects/<p>/` |
| `upgrade_state.py` | `_read_json` | `probation.json`, `blocklist.json` | `upgrade-state/` |
| `health_checks/upgrade_slot.py` | `check_upgrade_slot` | `active-slot` | `upgrade-state/` |
| `project_yaml.py` | `read_project_bytes` | a project's YAML file (`manifest.yml`, `compose.yml` and the files it includes; the staging base and a release tree's): see below. Cap: 1 MiB | `projects/<p>/` |
| `health_checks/projects.py` | `_drifted` | `<p>.conf`, compared with the generated site (capped at the size of a site file) | `caddy/sites/` |
| `commands/diff_cmd.py` | `run_diff` | `<p>.conf` and `compose.boxmunge.yml`, compared (the site cap; 1 MiB) | `caddy/sites/`, `projects/<p>/` |
| `commands/caddy_status.py` | `run_caddy_status` | each `<p>.conf`'s first line (the site cap) | `caddy/sites/` |
| `tui/project_detail.py` | `_caddy_text` | `<p>.conf`, shown (the site cap) | `caddy/sites/` |
| `compose_up_steps.py` | `sweep_live_scripts` | the generated compose overlay, searched for one string (1 MiB) | `projects/<p>/` |
| `secrets.py` | `_parse` | a project's `secrets.env`. Cap: 1 MiB | `projects/<p>/` |
| `commands/logs.py` | `_show_boxmunge_logs` | `boxmunge.log` and its archives | `logs/` |
| `commands/quarantine_gate.py` | `lift_after_deploy` | `<p>.conf`, the site a lift republishes (capped at the size of a site file) | `caddy/sites/` |

A project's YAML files go through `project_yaml.load_project_yaml` (`read_project_bytes` for the
bytes), as the `caddy.read_override` rules: a git project's `manifest.yml` and `compose.yml` are
links into `repo/`, so a link is followed when it resolves inside the project and no component of the
resolved path is swapped before the open. A release tree's files, never links, are read with no link
allowed. The parse is from a stream, so an error carries the parser's problem and line number and
never a line of the file (`yaml.safe_load` of a string quotes one, which would print a root-only
file's content for a link to it). Root's `docker compose config` follows the same links on its own;
that is for 0.12.

These open a no-follow, non-blocking descriptor themselves (`open_regular_nofollow` or
`open_resolved_nofollow`, read-only) and read from it, so each sets its own bound:

| Module | Functions |
|---|---|
| `backup.py` | `publish_new` |
| `bind_sources.py` | `_hash_file`, `_open_in_project` |
| `caddy.py` | `read_override` |
| `compose_images.py` | `_read_dockerfile` |
| `fileutil.py` | `durable_rename` |
| `log_rotation.py` | `first_entry_day`, `_archive` |
| `restore_safety.py` | `verify_plaintext` |
| `stash.py` | `_open_archive` |
| `commands/log_cmd.py` | `parse_log_file` |
| `commands/restore.py` | `_run_restore_command` |
| `commands/stage_cmd.py` | `_sha256` |
| `commands/upgrade_offline.py` | `_read` |
| `commands/userns_cmd.py` | `_held_on` |
| `health_checks/userns.py` | `_alert_state` |

An uploaded bundle in `inbox/` is the other deploy-written input. `bundle.inspect_bundle` is its
one bounded reader, shared by reception and extraction (the limits are at the top of `bundle.py`).

**Adding a reader.** Use a helper, add a row to `READERS` in `tests/test_root_state_reads.py` (its
link, FIFO and dangling-link tests then run on your reader), and add a row above.
`tests/test_root_reader_inventory.py` fails until all three are done. It also counts the reads
that go around the helpers (`open()`, `Path.read_text()` and the like) per module, so a new one
fails until you either use a helper or record the new count. That count is a baseline taken at
0.11.9, not a review of each existing read.

### Lock files

`flock` locks an inode, not a name. If a lock file is unlinked while a process holds it or is about
to take it, the next process creates a new file under the same name and both hold "the" lock. So a
lock file is never removed while anything can still take it, not even when the thing it guards is
removed: `project-delete` and `project-forget` leave the project's lock files behind, and a project
added again under the same name reuses them. Create a new lock under `state/` with
`fileutil.open_shared_lockfile` (no-follow, mode 0660, group `deploy`).

| Lock file | Taken with | Guards | Lifetime |
|---|---|---|---|
| `state/<project>.lock` | `fileutil.project_lock` (doesn't wait: `LockError`) | every command that changes the project | kept for good, after `project-delete` and `project-forget` too |
| `state/secrets-locks/<project>.lock` | `SecretsFile.locked` | writes of the project's secrets file | kept for good, as above |
| `state/secrets-locks/.host.lock` | `SecretsFile.locked` | writes of the host secrets file | kept for good |
| `state/.registry.lock` | `fileutil.registry_lock` | read, change and save of `projects.txt` | kept for good |
| `state/.caddy.lock` | `docker.caddy_config_lock` | writing Caddy site config and reloading | kept for good |
| `state/.legacy-stages.lock` | nothing since 0.11.7: `legacy-stage` took it, up to 0.11.6 | (the legacy-stage records) | left on a box where an older release made it |
| `state/container-updates/.lock` | `commands/container_update_cmd.py` (doesn't wait) | one container-update run at a time | kept for good |
| `logs/.<log name>.lock` | `log_rotation` (doesn't wait) | rotating that log | kept for good |
| `upgrade-root/upgrade.lock` | the upgrade shim, `upgrade_state.upgrade_lock` (doesn't wait: `UpgradeInProgress`) | one platform upgrade at a time | kept for good |
| `upgrade-state/upgrade.lock` | the same, together with the one above | upgrades started by a shim from 0.10.1 or earlier | kept while such a shim can still run; the shim replaces one that isn't root's (`acquire_lock` in `scripts/boxmunge-upgrade.d/state.sh`) |
| `state/.cve-grace.lock` | nothing: retired | (the v0.6 grace window) | deleted by the CVE scan where an old release left it |

`upgrade-root/` is root-only, so `deploy` can't replace the upgrade lock. The others are in
directories `deploy` can write: they serialise honest writers and aren't a defence against `deploy`.

## Testing

Four tiers, fastest first.

| Tier | Command | Needs | Covers |
|---|---|---|---|
| Unit | `make test` | Python | Logic, validation, policy, generated config; also the pinning, file-length, and sign-off lints |
| Client | `make test-cli` | Python | The PyPI client (CI also runs `services/version-check/`'s own tests) |
| Integration | `make test-integration` | Docker, `age` | Real compose deploys, Caddy, backup and restore round-trips, MCP |
| Full system | `make test-vm` | QEMU, `mkisofs`, the client | Boots Debian 13, runs `server-setup`, deploys, backs up, restores (see `tests/vm/README.md`) |

Tests that need Docker carry the `integration` marker, wherever they live; `make test` deselects
them and `make test-integration` selects them. Integration tests skip when Docker or `age` is missing. CI sets `BOXMUNGE_REQUIRE_INTEGRATION=1`,
which turns a missing prerequisite into a failure, so a green CI run means they actually ran.

CI splits the integration tests and the remapped-daemon (`userns-dind`) tests into parallel shards
of whole test files (`--shard K/N`, `tests/shard.py`), balanced by the seconds per file in
`tests/shard_weights.json`. A module marked `shard_by_test` is split test by test instead, for
tests long enough to dominate a shard (the userns migration crash sweeps); its tests must not
depend on each other. A new file runs in some shard from its first commit, weighed as the average;
stale weights only unbalance the shards. Each sharded CI job prints its seconds per unit last; to
refresh the weights, merge those, or run a tier with `--store-shard-weights
tests/shard_weights.json`.

Every integration test that backs up, restores or syncs runs through a real `boxmunge-system`
container, built from `system/Dockerfile` and started from `system/compose.yml` on the test root
(the `real_system_container` fixture; it uses a unique container name). There is no host fallback.
`tests/integration/test_system_container_tier.py` adds a tripwire that fails if age or rclone is
handed a path outside `/projects` or `/config`, or runs on the host. Docker Desktop on macOS hides
uid and ownership bugs, so the Linux CI run is authoritative for that tier.

Prefer tests that exercise real behaviour. A test that mocks `subprocess.run` for the very code
under test passes whether the code works or not. When you need Docker or git behaviour, use the
integration tier.

Lint with `make lint` (ruff, configured in `ruff.toml`).

## Dependencies are hash-pinned

Every install in CI uses `pip install --require-hashes` against checked-in requirements files, and
so do on-box installs: `install.sh` and the upgrade shim install from the `requirements-build.txt`
(the setuptools build backend), `requirements-tui.txt` and `requirements-mcp.txt` shipped in the
signed bundle. MCP is always installed, not opt-in: the shim builds each venv slot from scratch, so
anything else would be lost on the next upgrade. Likewise,
every GitHub Action is pinned to a commit SHA. `tests/test_release_pinning.py` fails the build if
either rule is broken. To change a dependency, edit the matching `.in` file or `pyproject.toml`, run
`make lock`, and commit the regenerated `.txt` files. Dependabot proposes routine bumps: each
week, one pull request per ecosystem (pip, Actions, Docker) for minor and patch updates, and one per
major, for releases at least 7 days old (a pip major waits 30). See `.github/dependabot.yml`.

Dependabot does not regenerate the runtime locks built from `pyproject.toml` (`requirements.txt`,
`requirements-tui.txt`, `requirements-mcp.txt`, `cli/requirements.txt`), so they are re-locked by
hand: `make relock` (with the pip and pip-tools from `requirements-dev.txt`) upgrades them, taking
no release younger than the same 7-day cooldown. It holds back the majors listed in
`relock-holds.txt`: taking one is a decision of its own, made with whatever code change it needs.
Re-lock before each release, respecting the cooldown (release step 1 below). CI fails a release
pull request (a `release/*` branch) while a runtime pin is behind a same-major release (for a
calendar-versioned package such as certifi, any newer release) that has been out for more than 14
days (`scripts/lock-freshness.py`). `requirements-dev.txt` may pin another version of a package a
runtime lock also pins (click, idna, pygments): nothing installs them in one pip run.

## How a release reaches a server

1. A maintainer re-locks the runtime dependencies (`make relock`; see "Dependencies are
   hash-pinned" above): re-lock before each release, respecting the cooldown. Check the advisories
   fixed by the pins that moved (`pip-audit --require-hashes --disable-pip -r FILE` on the old and
   new locks): they belong in the release notes, and may make it a `security` release.
2. A maintainer bumps `version` in `pyproject.toml`, records the release, its class and whether it
   is breaking in `services/version-check/releases.json` (`"class": "feature"`, `"breakfix"` or
   `"security"`; `"breaking": true` or `false`), and tags `vX.Y.Z`. A unit test fails if the
   `pyproject.toml` version is not listed. The version-check service refuses to start if any entry
   lacks either field, and the release workflow refuses a breaking release whose version is not
   `X.Y.0`, or one without `upgrade-notes/X.Y.Z.json` (see "Upgrade notes" below).
3. `.github/workflows/release.yml` checks the tag with `scripts/release-lint.py` (listed in
   `releases.json` with a valid class, matching `pyproject.toml`), then, in a read-only job, runs
   the tests, builds the installer and bundle, and generates an SBOM (`scripts/generate-sbom.sh`:
   the package and every hash-pinned dependency a box installs, plus age, rclone and the images
   boxes pull, validated as CycloneDX). A separate job holding the write and signing tokens
   signs `SHA256SUMS` with cosign (keyless, tied to this workflow and tag), creates a draft
   release whose title and notes carry the class marker (and `[breaking]` for a breaking
   release) generated from `releases.json`, verifies the draft carries exactly those markers,
   and publishes it. Any failure, including signing, fails the workflow. The notes
   are that generated preamble followed by GitHub's generated changelog, the pull requests since
   the previous release. The changelog quotes PR titles, so the workflow turns any marker in it
   into plain text (`[held]` becomes `(held)`) first: a PR title cannot reclassify a release or
   stop it being published. Edit the published notes by hand if you want more than the changelog,
   and keep markers out of what you add (`audit` below checks).
4. Once the release is published, the maintainer redeploys the version-check service so it serves
   the new `releases.json`. Do not redeploy it before then: it would offer a release boxes cannot
   download yet. Servers discover new releases through that service, with the GitHub releases
   list (and its `[security]` / `[breakfix]` / `[breaking]` markers) as the fallback only when
   the service cannot be reached at all; an error answer from it is not a reason to fall back
   (see "Holding a broken release" below for the `[held]` marker). If you
   change an existing entry in `releases.json`, edit that release's title on GitHub to match, and
   confirm with `python scripts/release-lint.py audit --github-releases FILE`, where FILE is the
   output of `gh api --paginate --slurp 'repos/boxmunge/boxmunge/releases?per_page=100'`.
5. `scripts/boxmunge-upgrade` downloads the release, verifies the cosign signature against this
   repository's release workflow identity, checks the checksums, installs into the standby venv,
   swaps, and watches a probation window. A release that fails probation is rolled back and
   blocklisted.

Security releases apply automatically. Break-fix releases (important fixes that prevent issues;
you shouldn't fall behind on them) apply automatically unless the box sets
`auto_update.breakfix: false` in `boxmunge.yml`. Feature releases wait for the operator to run
`upgrade`. The `breakfix` class is about prevention, not urgency: use it for a non-security fix that
keeps boxes from running into trouble later and that every box should take. A fix for a
vulnerability is always `security`.

Set `"breaking": true` on any release that changes an operator workflow, or could make an existing
project, manifest, compose file, command line or upload method fail. A breaking release bumps the
minor version (`X.Y.0`). Automatic security and break-fix updates cross minor lines, but never a
breaking release and never a major version: a box behind a breaking release is told to upgrade by
hand instead. So mark honestly. A breaking release marked `false` would be installed on boxes
unattended, and a fix marked `breaking` stops reaching older lines automatically.
The full trust chain is in `docs/on-server/TRUST_MODEL.md`.

The client is published to PyPI by `.github/workflows/publish-cli.yml` on a `cli-v*` tag, using
PyPI Trusted Publishing, so no API token exists anywhere.

### The upgrade floor

A release installs only over 0.11.0 or later: `UPGRADE_FLOOR` in `src/boxmunge/upgrade_floor.py`,
and the same value in `bootstrap/upgrade-floor.sh` for an `install.sh` run by hand (a test keeps
the two equal). Below the floor the release refuses in the old shim's pre-flight, before that
shim changes anything, and names the bridge release (`BRIDGE_RELEASE`, 0.11.6): the last
release that installs over an older box. `tests/integration/test_shim_hop.py` runs released
shims against the tree. Below the floor it proves the refusal leaves the box on its release and
still able to install the bridge release; from the floor up, that the hop completes.

Code that exists only for a source below the floor is deleted. Code kept for a source above it
says, where it lives, which floor retires it. Today that is 0.11.1 (the `report_failure` probe
in the shim; re-owning root-made directories in `deploy_dirs.py`), 0.11.5 (a rollback with no
recorded stash), 0.11.6 (adopting a probation with no root record) and 0.11.7 (the shim's
legacy lock; `bootstrap/caddy-log-path.sh`, which refuses a box whose Caddy configs write a log
under `/var/log/caddy`; `unresolved_stage.py`, which refuses a box that still holds a stage
0.10.1 or earlier made, with `unresolved_stage_install.py` and `bootstrap/unresolved-stage.sh`,
which ask it for an `install.sh` run by hand).

To raise the floor, announce it in the release notes of the release that becomes the bridge,
then in the next release change the constants in both files, move the hop test's shims across,
and delete what the new floor retires.

### Upgrade notes

Every release from 0.11.8 has `upgrade-notes/X.Y.Z.json`: what it asks of projects and boxes, as
data. The release workflow's publish job compiles every file up to the tag into
`upgrade-notes.json` (`scripts/release-lint.py upgrade-notes`, stdlib only) and lists it in the
signed `SHA256SUMS`. On a box, `upgrade-howto` verifies it as an upgrade verifies a bundle, then
shows the entries introduced after the box's release, up to the target, minus superseded ones.
A box below the upgrade floor is shown none: it is told to reach the bridge release by hand first.

```json
{"version": "0.12.0", "no_project_action": false, "entries": [
  {"id": "0.12.0-python-floor", "scope": "box", "when": "before", "kind": "required",
   "title": "...", "change": "...", "verify": "...",
   "files": [], "superseded_by": null, "refs": ["#231"]}]}
```

- `scope` is `box` or `project`; `when` is `before` or `after` the box upgrade; `kind` is
  `required`, `recommended` or `fact`.
- `files` names what a project entry asks an agent to check: one or more of `manifest.yml`,
  `compose.yml` and `Dockerfile`. A box entry has `[]`.
- `id` is `<version>-<slug>`, the slug in lowercase letters, digits and hyphens.
- `title` (one line, at most 100 characters), `change` (1000) and `verify` (500) hold printable
  characters, plus newlines outside the title. Agents act on this text: write it as instructions
  to one, and say how to check the change was made.
- `superseded_by`: when a later release replaces an entry's advice, the PR that does so sets the
  old entry's `superseded_by` to the new release, and the guide shows only the new entry.
- `refs`: the PRs or issues behind the entry, like `#231`.
- A release that asks nothing says so:
  `{"version": "X.Y.Z", "no_project_action": true, "entries": []}`.

`release-lint.py check` refuses a tag whose file is missing or invalid, and a unit test loads
every file on every pull request. The rule from 0.12 on: a PR with project or box impact adds
its entry to the next release's file in the same PR. Releases before 0.11.8 have no file:
`upgrade-howto` first ships in 0.11.8, and a box is only shown entries newer than its own
release, so no box could ever be shown them.

Boxes on older releases read the compiled file, so `src/boxmunge/upgrade_notes.py` ignores keys
it does not know. Adding a key is fine; a new `scope`, `when`, `kind` or class value, or a key
whose meaning changes, needs `FORMAT` 2, and boxes on earlier releases then cannot compose a
guide from that release's notes.

## The version-check admin pages

`services/version-check` serves two maintainer-only views of update checks and failure reports,
each with its own credential, never interchangeable:

- `/v1/admin/stats` (HTML, for a browser) shows daily checks per version, each network prefix
  (IPv4 /24, IPv6 /48) that checked in the last 90 days with its latest version and first and
  last day seen, and recent failure reports with their prefix. It needs a passkey sign-in. Signing in sets an 8-hour
  session cookie (`Path=/v1/admin`, HttpOnly, Secure, SameSite=Strict). Its signing key needs both
  `STATS_SECRET` and a random key created in the service's database on first start, so the
  Bearer secret alone cannot forge a session. Without a session, the page redirects to
  `/v1/admin/login`.
- `/v1/admin/version-checks` (JSON, for scripts) needs `Authorization: Bearer <STATS_SECRET>`.
  The session cookie does not open it, and the HTML page ignores the Bearer header.

Without `STATS_SECRET`, or with one shorter than 32 characters, every admin route answers 503 and
names the setting. Wrong secrets, whether sent as a Bearer header or as the registration code,
count against one limit per client (10 per 15 minutes) in each worker: gunicorn runs two, and
each counts on its own, so a client can make up to 20 wrong guesses per window. Past it, that
client is refused even with the right secret until the window ends. Each worker tracks at
most 10,000 guessing clients per window; one IPv6 /48 holds enough /64s to fill that, so once
it is full a new client is counted by its network (IPv4 /24 or IPv6 /48, 20 wrong guesses per
window) instead, and a flood locks out only its own network. Only when 10,000 networks are
tracked too is every new client refused the same way (fail closed). Each client (IPv4 address or IPv6 /64) may start
5 sign-in or registration ceremonies per 5 minutes in each worker, and each network (IPv4 /24 or
IPv6 /48) 20, both counted in memory: one client cannot block another's sign-in, the many /64s
of one /48 cannot fill the database's global backstop of 10,000 pending challenges, and no
address is stored. The relying
party is `ADMIN_RP_ID` (default `boxmunge.dev`) with origin `https://<ADMIN_RP_ID>`, so the passkey
works on the production host only, not on `staging.<host>`. One passkey can be registered. It must
use ES256 or EdDSA, and the authenticator must verify the user.

### First-time setup

1. Set the registration code (it is `STATS_SECRET`, at least 32 characters), from the deploy
   shell: `secrets set boxmunge-web STATS_SECRET=<value>`, generating the value with
   `openssl rand -hex 32`.
2. Redeploy the service (`stage boxmunge-web`, then `promote boxmunge-web`) so it reads the secret.
3. Open `https://boxmunge.dev/v1/admin/register`, paste the code into the form, and create the
   passkey when the browser asks. Registration then closes.
4. Sign in at `https://boxmunge.dev/v1/admin/login`.

The code goes only in the form, never in a URL.

### Recovery

If the passkey is lost, or you suspect `STATS_SECRET` has leaked, set a new `STATS_SECRET` and
redeploy (`openssl rand -hex 32` again). The stored passkey was registered under the old code, so it is ignored and registration
reopens. Every existing session ends too, because the session key changes. Then repeat steps 3
and 4. Nothing on the web resets the passkey.

## Holding a broken release

The version-check circuit breaker withholds a broken release from every box that can reach
the service: a security or break-fix release is withdrawn from automatic updates, and any
release, a feature release included, is refused by a manual `upgrade` (which installs the
newest unheld release instead, or names `upgrade --target X.Y.Z` to install the held one
deliberately). Trip it, then mark the hold on GitHub, so that boxes which
cannot reach the service (and fall back to the GitHub releases list) hold it too:

```bash
curl --fail-with-body -X POST -H "Authorization: Bearer $CB_SECRET" \
  'https://boxmunge.dev/v1/circuit-breaker/trip?version=X.Y.Z' &&
t=$(gh release view vX.Y.Z --json name -q .name) &&
case "$t" in *"[held]"*) ;; *) gh release edit vX.Y.Z --title "$t [held]" ;; esac
```

`--fail-with-body` matters: without it curl exits 0 on a refused trip (401, 429, 503), and
GitHub would say held while the service still offers the release. The title keeps its class
and breaking markers, and a title already marked `[held]` is left alone.

`CB_SECRET` (set through the deploy shell, like `STATS_SECRET`) must be at least 32
characters (`openssl rand -hex 32`): a shorter one stops the service from starting, naming
it, and with none set the trip and reset endpoints refuse with 503. Wrong guesses of it share
`STATS_SECRET`'s limit (10 per client per gunicorn worker in 15 minutes); past it, even the
right secret is refused with 429 until the window passes, so trip from a client that has not
been guessing.

Boxes read `[held]` from the release title only, never from the notes (auto-generated notes
quote contributors' PR titles), so only someone with write access to the repository can set
it. The release workflow neutralises `[held]` in the changelog it generates and refuses to
publish a draft still carrying it anywhere: a release is published unheld and held afterwards. To release the hold, reset the breaker
(`/v1/circuit-breaker/reset?version=X.Y.Z`) and take `[held]` out of the title again. Check
that GitHub matches the service with
`python scripts/release-lint.py audit --github-releases FILE --held X.Y.Z` (one `--held`
per held version, none when nothing is held); it fails on a hold missing on either side and
on a `[held]` left in release notes, where it does nothing.

Failure reports never hold a release: they are unauthenticated, so anyone with addresses in
a few networks (IPv4 /24s, or IPv6 /48s, which are cheap) could send them, and only the
maintainer trips the breaker. They alert instead. When reports for a release come from two or
more distinct networks in six hours (`ALERT_NETWORKS` in `failure_alert.py`), and the release
is not held, the service's smoke script fails as a warning with one line naming the release
and the commands above for it. It does so only on boxmunge's periodic health check
(`BOXMUNGE_CHECK=periodic`, which `check-all` alone sets): every other smoke run gates an
operation (deploy, recover, a quarantine lift, resume, userns bring-up), and reports anyone
can send must never hold one up. boxmunge's health check on the box that
runs the service turns that into a Pushover alert after `health.alert_threshold` checks in a
row, once per distinct message: the line carries no counts, so further reports do not alert
again. The warning clears, with a recovery alert, at the first check after the release is held, or
once its reports are older than six hours; a later crossing alerts again.
Only the network a report comes from counts; nothing in a report's body, a box ID least of
all, may ever count, because the sender writes it. Before holding, read the reports: the
stats page lists them, every distinct failure a network reports is kept, and
`/v1/failures?version=X.Y.Z` counts the reports (by stage) and the networks that sent them.
The `CIRCUIT_BREAKER_AUTO_THRESHOLD` setting that used to let reports trip the breaker was
removed in 0.11.6; a service started with it still set prints a warning saying so at every
start, and it should be taken out of the service's environment.

For sizing the `check-data` volume: a network stores at most 10 rows (about 200 bytes each)
per listed version per six-hour window, so at most 40 a day per network and version, kept
90 days.

The service's limits are per gunicorn worker. Beyond the per-client request limit, a flood
of distinct clients that fills a worker's table (100,000) no longer locks out every box that
has not checked yet: a new client is then limited by its network (600 requests a minute per
IPv4 /24 or IPv6 /48), so the flood exhausts only its own networks.

The service's backup (`backup boxmunge-web`) runs `backup_db.py`, which copies the database
through SQLite's backup API, never the file itself, while the service runs. Its restore checks
a snapshot before writing it, and needs the service stopped: any connection inside a
transaction holds a lock it waits for, then it gives up. Restore with `restore boxmunge-web`,
which stops the project, runs the restore in the backup service alone and recreates the
service on the restored data; never run `backup_db.py restore` against the service while it
serves.
