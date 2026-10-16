# boxmunge

The local CLI for [boxmunge](https://github.com/boxmunge/boxmunge): deploy your
side projects to a single VPS, without carrying Docker networking, Caddy config
and firewall rules around in your head.

This package is the **client**. It scaffolds and bundles a project, uploads it,
and drives the server over SSH. The server (`boxmunge-server`) is installed on
your VPS from signed GitHub releases, not from PyPI; `boxmunge server-setup`
does that for you.

## Install

```bash
pipx install boxmunge      # or: pip install boxmunge
```

Python 3.10+. `server-setup` also needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
on your machine to verify the release it installs.

## Quickstart

```bash
# 1. Turn a fresh Debian 13 (x86_64) VPS into a boxmunge server
boxmunge server-setup root@box.example.com --email you@example.com

# 2. Scaffold a project (or run init in an existing one)
mkdir myapp && cd myapp
boxmunge init --server box.example.com --host myapp.example.com

# 3. Register it on the server (once), then ship it
boxmunge remote project-add myapp
boxmunge stage            # bundle, upload, deploy to staging.<server>
boxmunge promote          # staging becomes production
#    or: boxmunge prod-deploy   (skip staging)
```

`server-setup` downloads the latest release and verifies it locally before it
touches the server: cosign checks the keyless signature on `SHA256SUMS`
against the boxmunge release workflow, and the installer must match
`SHA256SUMS`. It also verifies the server's SSH host key: a server not yet in
`~/.ssh/known_hosts` must match `--host-key-fingerprint SHA256:...` (shown by
your VPS provider, or by `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`
on the server's console), or be confirmed at the terminal. An IP target needs
`--hostname`. Run `boxmunge server-setup --help` for every option.

## Commands

| Command | What it does |
|---|---|
| `init --server HOST [--host NAME]` | Write `.boxmunge` and scaffold a project |
| `bundle [DIR] [--list] [--validate] [--json]` | Build `<project>-<timestamp>.tar.gz` |
| `stage [--dry-run]` | Bundle, upload, stage |
| `promote [--dry-run]` | Promote staging to production |
| `prod-deploy [--dry-run] [--no-snapshot]` | Bundle, upload, deploy to production |
| `prod-deploy --abandon` | Undo an interrupted install before its pre-deploy hook ran |
| `rollback [--yes]` | Roll production back to the previous deploy |
| `status [--json]` | The server's project dashboard |
| `logs [SERVICE] [--tail N] [--follow]` | This project's logs |
| `secrets set\|get\|list\|unset [KEY]` | This project's secrets on the server |
| `validate [--json]` | Validate the deployed project on the server |
| `remote COMMAND [ARGS...]` | Any other server command, e.g. `remote inbox` |
| `mcp-serve [--server HOST]` | MCP stdio proxy to the server |
| `server-setup [user@]host --email EMAIL` | Set up a fresh VPS |

Every command has `--help`. Errors go to stderr and start with `ERROR:`. Exit
codes: 0 success, 1 failure, 2 usage error, 3 client and server incompatible,
4 server unreachable; commands that run a server command exit with its code.

## The scaffold

`boxmunge init` writes a project that deploys as-is once its host is set:
`manifest.yml` (schema 3, a fixed project id, limits, a smoke test),
`compose.yml`, a multi-stage `Dockerfile` on a slim Python base running as a
non-root user, a minimal `app.py`, `project.env` for non-secret settings, and a
POSIX `boxmunge-scripts/smoke.sh`. Without `--host` the manifest has a
`<project>.change-me.invalid` placeholder, and bundling refuses it. Pin the
Dockerfile's base image by digest before deploying (the file says how).

## `.boxmunge`

`init` writes it in the project root; commands find it in the current
directory or a parent, stopping at the repository root and never reading one
in your home directory.

```yaml
server: box.example.com   # hostname or IP (IPv6 without brackets)
port: 922                 # boxmunge's SSH port
user: deploy              # the restricted deploy user
project: myapp            # must equal 'project' in manifest.yml
```

Unknown keys are errors. If `.boxmunge` and `manifest.yml` name different
projects, nothing is uploaded.

## What goes into a bundle

Everything in the project directory except:

- never shipped: `.git/`, `.hg/`, `.svn/`, `.env` and `.env.*` (but
  `.env.example` ships), and `.boxmunge`;
- left out by default: `node_modules/`, `.venv/`, `venv/`, `__pycache__/`,
  `*.pyc`, tool caches, `.DS_Store`, earlier bundles, and the top-level
  `data/` and `backups/` (re-include with a `!pattern` line);
- anything matched by `.boxmungeignore` (gitignore syntax).

Bundling stops with an error for `secrets.env` (set secrets with
`boxmunge secrets set` instead), a top-level `repo/`, symlinks that are
absolute or leave the project, and special files, unless `.boxmungeignore`
leaves them out. `boxmunge bundle --list` shows the plan without writing.

`stage` and `prod-deploy` upload with `scp -O` (the legacy scp protocol): the
deploy user has no SFTP subsystem, and OpenSSH 9's scp uses SFTP by default.
This needs OpenSSH 8.7 or newer on your machine. To upload by hand, use
`scp -O -P 922 myapp-<timestamp>.tar.gz deploy@<server>:`.

The client checks only the manifest's shape. The server validates the full
manifest on `stage` and `prod-deploy` before it changes anything; add
`--dry-run` to run that check without deploying.

If a `prod-deploy` is interrupted or fails before the project's pre-deploy
hook ran, `boxmunge prod-deploy --abandon` uploads nothing and runs
`prod-deploy <project> --abandon` on the server: the previous release's files
go back (a first deploy's code is removed), and containers and data were never
touched. Once a hook may have run, use `boxmunge rollback` instead. Servers
older than the release that added it refuse it as an unknown argument.

## MCP

Agent hosts usually start MCP servers outside your project, and the server's
MCP is server-wide, so name the server explicitly:

```json
{
  "mcpServers": {
    "boxmunge": {
      "command": "boxmunge",
      "args": ["mcp-serve", "--server", "box.example.com"]
    }
  }
}
```

`--port` and `--user` default to 922 and `deploy`; `--config PATH` reads a
`.boxmunge` instead. The proxy never prompts (ssh BatchMode), so use an SSH key
from your agent or an unencrypted key. The server installs its MCP support with the
platform; if the server's `mcp-serve` reports it missing, its error says how to repair it.

## Versions

The client and server release independently. On every server command the
client runs a handshake: the server states the oldest client it accepts, the
client requires boxmunge-server 0.10.0 or newer, and a manifest whose
`schema_version` is newer than the server understands is refused before upload.
Upgrade the client with `pipx upgrade boxmunge` (or `pip install -U boxmunge`).

## Links

- [Source and documentation](https://github.com/boxmunge/boxmunge)
- [Issue tracker](https://github.com/boxmunge/boxmunge/issues)

Licensed under Apache-2.0.
