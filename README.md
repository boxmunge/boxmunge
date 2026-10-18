# boxmunge

You've got side projects. Maybe five, maybe ten. Each one needs a server, TLS certificates, backups, security patches — and every one of them gets about 200 visitors a month. You're paying for separate VPSes, or you crammed everything onto one box and hope nothing collides. Backups? You set them up once. You've never tested a restore.

## One server, all your projects, everything handled

Bring a fresh Debian VPS. Point your projects at it. Go back to building things.

boxmunge turns a single server into a managed home for all your web projects. Each project gets its own Docker Compose setup, its own domain, its own backups — but they share the same box, the same automatic TLS, the same security hardening. You don't configure any of that. It's just there.

And here's what makes it feel like 2026: **your AI agent can run the whole thing.** Every day-to-day boxmunge command works over SSH, so the same agent that helps you write code can deploy it, check on it, back it up, and restore it. You don't need to learn boxmunge. You don't need to learn Docker networking or Caddy configuration or UFW rules. You build your web project, your agent handles the rest.

That's the real promise — not just "easy hosting," but one less tool you have to carry in your head.

### What you get

- **All your projects on one VPS** — each isolated in Docker Compose, sharing the server
- **Automatic HTTPS** — Caddy + Let's Encrypt, zero configuration
- **Encrypted backups that actually restore** — mandatory restore commands; `self-test` proves the backup and restore pipeline on a canary project
- **Staged deploys** — stage a release beside production, verify it, promote it. Promoting
  recreates production's containers from the staged release, so expect a restart's worth of
  downtime; a stage that copies production's data (`staging.copy_data`) stops production for the
  copy
- **Host security hardening out of the box** — firewall, intrusion detection, kernel hardening, automatic security updates
- **Signed releases** — every release's `SHA256SUMS` is keyless-signed via Sigstore (cosign + Fulcio + Rekor), and the upgrade shim verifies the signature against this repo's release workflow before installing — unsigned releases are refused
- **Per-container security hardening** — every service runs with no-new-privileges, dropped Linux capabilities, and PID limits by default; built images run as a non-root user unless the manifest says otherwise, and Docker remaps user namespaces so a container's root is an unprivileged host user (from the first boot on a new server; an existing one migrates once, when the operator runs `boxmunge-upgrade userns-migrate`); see `agent-help security` on the server
- **AI-native operations** — every day-to-day command works over SSH, and the core lifecycle commands via MCP; designed for agents from day one

## Getting started

### 1. Set up your server

You need a fresh Debian 13 VPS with a public IP. Download the latest self-extracting installer, copy it to the server, and run it as root with your hostname, contact email, and SSH public key:

```bash
# Locally — fetch the installer and capture your SSH public key
curl -fsSLO https://github.com/boxmunge/boxmunge/releases/latest/download/boxmunge-install.sh
scp boxmunge-install.sh root@your-server.example.com:
SSH_KEY="$(cat ~/.ssh/id_ed25519.pub)"

# On the server — run as root
ssh root@your-server.example.com "bash boxmunge-install.sh \
    --hostname your-server.example.com \
    --email you@example.com \
    --ssh-key '${SSH_KEY}'"
```

That's it. The installer carries the entire boxmunge bundle inside it — installs Docker, hardens the OS, sets up Caddy as a reverse proxy in a container, creates the `deploy` and `supervisor` users, and lays down the boxmunge CLI on the server. Takes a few minutes.

Or let the client do it from your machine: `pipx install boxmunge`, then
`boxmunge server-setup root@your-server.example.com --email you@example.com`. It verifies the
release's cosign signature and checksums locally and the server's SSH host key before installing
anything. See [INSTALL.md](INSTALL.md).

### 2. Ship a project

Install the client and scaffold a project. `boxmunge init` writes `.boxmunge` (which server to deploy
to) and, in a directory without a manifest, a project that deploys as-is: a `manifest.yml` that tells
boxmunge what you're running, a `compose.yml`, a hardened `Dockerfile`, and a smoke test. Or get your
AI agent to adapt it to your app.

```bash
pipx install boxmunge                         # see INSTALL.md
cd myapp
boxmunge init --server your-server.example.com --host myapp.example.com
boxmunge remote project-add myapp            # once: register the project on the server
boxmunge stage                                # bundle, upload, deploy to staging.myapp.example.com
boxmunge promote                              # deploy the staged release to production
```

A manifest looks like this (`init` writes one with a project id):

```yaml
schema_version: 3
id: 01JQXYZ1234567890ABCDEFGHJ
project: myapp
source: bundle
hosts:
  - myapp.example.com
services:
  web:
    port: 8080
    routes:
      - path: /
  db:                          # postgres, from compose.yml: who it runs as
    security:
      user: image
      reason: "postgres entrypoint drops to postgres"
backup:
  type: postgres
  service: db
  dump_command: "pg_dump -U myuser mydb"
  restore_command: "psql -U myuser mydb"
```

Your project is live at `https://myapp.example.com` with TLS, reverse proxy, and backups configured.

### 3. Let your agent take over

The server installs its MCP support with everything else, from hash-pinned requirements, and
every platform upgrade installs it again. Add boxmunge to your AI agent's MCP configuration. The
client's `mcp-serve` relays the protocol over SSH to the server's `mcp-serve`:

```json
{
  "mcpServers": {
    "boxmunge": {
      "command": "boxmunge",
      "args": ["mcp-serve", "--server", "your-server.example.com"]
    }
  }
}
```

Inside a project, the client's other commands read `.boxmunge` to find the server, and refuse to deploy if it names a different project than `manifest.yml`. Now "deploy it" is a conversation, not a context switch.

## Commands

SSH into the deploy user and run commands directly — no `boxmunge` prefix needed:

| Command | Description |
|---------|-------------|
| `stage <project>` | Deploy to staging for verification |
| `promote <project>` | Promote staging to production |
| `prod-deploy <project>` | Deploy straight to production |
| `rollback <project>` | Restore pre-deploy snapshot and redeploy |
| `backup <project>` | Create encrypted backup |
| `restore <project>` | Restore from backup |
| `self-test` | Prove backup/restore pipeline actually works |
| `health` | Platform audit |
| `status` | Dashboard of all projects |
| `secrets set/get/list/unset` | Manage project secrets |
| `upgrade` | Update the platform |
| `log` | Query operational logs |

## Documentation

- [Client install](INSTALL.md) — installing the `boxmunge` client on your workstation ([commands](cli/README.md))
- [Architecture](docs/on-server/ARCHITECTURE.md) — system design and components
- [Operations](docs/on-server/OPERATIONS.md) — step-by-step guides
- [Project Conventions](docs/on-server/PROJECT_CONVENTIONS.md) — manifest format
- [Trust Model](docs/on-server/TRUST_MODEL.md) — security model and boundaries
- [Container Security](docs/on-server/SECURITY.md) — per-container hardening details
- [Contributing](CONTRIBUTING.md) — how to contribute
- [Security Policy](SECURITY.md) — reporting vulnerabilities
- [Code of Conduct](CODE_OF_CONDUCT.md)

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
