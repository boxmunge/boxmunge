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

**This is changing.** A single action registry with typed results and capability tiers is being
built so the CLI, shell, MCP, and plugins all derive from one definition. Until it lands, adding a
command means touching several places, listed below.

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
5. Add it to `HELP_TEXT` in `src/boxmunge/commands/help.py`, give it a usage entry in
   `USAGE` in `src/boxmunge/commands/usage.py` (what `help <command>` prints; a test fails until
   every registered command has one), and document it in `docs/on-server/OPERATIONS.md`.
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
| `/opt/boxmunge/state/` | deploy | registry, locks, health, deploy, staging, scan, KEV, container-update and platform-update state |
| `/opt/boxmunge/upgrade-state/` | root:deploy | active venv slot, probation, blocklist |
| `/opt/boxmunge/logs/boxmunge.log` | deploy, group-writable | structured JSON-lines operational log, written by root and deploy |
| `/opt/boxmunge/caddy/` | root:deploy | Caddyfile and generated `sites/*.conf` |

`src/boxmunge/paths.py` is the source of truth for every path.

## Testing

Three tiers, fastest first.

| Tier | Command | Needs | Covers |
|---|---|---|---|
| Unit | `make test` | Python | Logic, validation, policy, generated config; also the pinning, file-length, and sign-off lints |
| Client | `make test-cli` | Python | The PyPI client |
| Integration | `make test-integration` | Docker, `age` | Real compose deploys, Caddy, backup and restore round-trips, MCP |
| Full system | `make test-vm` | QEMU, `mkisofs`, the client | Boots Debian 13, runs `server-setup`, deploys, backs up, restores (see `tests/vm/README.md`) |

Tests that need Docker carry the `integration` marker, wherever they live; `make test` deselects
them and `make test-integration` selects them. Integration tests skip when Docker or `age` is missing. CI sets `BOXMUNGE_REQUIRE_INTEGRATION=1`,
which turns a missing prerequisite into a failure, so a green CI run means they actually ran.

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
so do on-box installs: `install.sh` and the upgrade shim install from the `requirements-tui.txt` and
`requirements-build.txt` (the setuptools build backend) shipped in the signed bundle. Likewise,
every GitHub Action is pinned to a commit SHA. `tests/test_release_pinning.py` fails the build if
either rule is broken. To change a dependency, edit the matching `.in` file or `pyproject.toml`, run
`make lock`, and commit the regenerated `.txt` files. Dependabot proposes routine bumps.

## How a release reaches a server

1. A maintainer bumps `version` in `pyproject.toml`, records the release, its class and whether it
   is breaking in `services/version-check/releases.json` (`"class": "feature"`, `"breakfix"` or
   `"security"`; `"breaking": true` or `false`), and tags `vX.Y.Z`. A unit test fails if the
   `pyproject.toml` version is not listed. The version-check service refuses to start if any entry
   lacks either field, and the release workflow refuses a breaking release whose version is not
   `X.Y.0`.
2. `.github/workflows/release.yml` checks the tag with `scripts/release-lint.py` (listed in
   `releases.json` with a valid class, matching `pyproject.toml`), then, in a read-only job, runs
   the tests, builds the installer and bundle, and generates an SBOM. A separate job holding the
   write and signing tokens signs `SHA256SUMS` with cosign (keyless, tied to this workflow and
   tag), creates a draft release whose title and notes carry the class marker (and `[breaking]`
   for a breaking release) generated from `releases.json`, verifies the draft carries exactly
   those markers, and publishes it. Any failure, including signing, fails the workflow.
3. Once the release is published, the maintainer redeploys the version-check service so it serves
   the new `releases.json`. Do not redeploy it before then: it would offer a release boxes cannot
   download yet. Servers discover new releases through that service, with the GitHub releases
   list (and its `[security]` / `[breakfix]` / `[breaking]` markers) as the fallback. If you
   change an existing entry in `releases.json`, edit that release's title on GitHub to match, and
   confirm with `python scripts/release-lint.py audit --github-releases FILE`, where FILE is the
   output of `gh api --paginate --slurp 'repos/boxmunge/boxmunge/releases?per_page=100'`.
4. `scripts/boxmunge-upgrade` downloads the release, verifies the cosign signature against this
   repository's release workflow identity, checks the checksums, installs into the standby venv,
   swaps, and watches a probation window. A release that fails probation is rolled back and
   blocklisted.

Security releases apply automatically. Break-fix releases (critical non-security fixes) apply
automatically unless the box sets `auto_update.breakfix: false` in `boxmunge.yml`. Feature releases
wait for the operator to run `upgrade`. Use `breakfix` only for a fix that cannot wait for the
operator; a fix for a vulnerability is always `security`.

Set `"breaking": true` on any release that changes an operator workflow, or could make an existing
project, manifest, compose file, command line or upload method fail. A breaking release bumps the
minor version (`X.Y.0`). Automatic security and break-fix updates cross minor lines, but never a
breaking release and never a major version: a box behind a breaking release is told to upgrade by
hand instead. So mark honestly. A breaking release marked `false` would be installed on boxes
unattended, and a fix marked `breaking` stops reaching older lines automatically.
The full trust chain is in `docs/on-server/TRUST_MODEL.md`.

The client is published to PyPI by `.github/workflows/publish-cli.yml` on a `cli-v*` tag, using
PyPI Trusted Publishing, so no API token exists anywhere.
