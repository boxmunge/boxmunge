# boxmunge

You've got side projects. Maybe five, maybe ten. Each one needs a server, TLS certificates, backups, security patches — and every one of them gets about 200 visitors a month. You're paying for separate VPSes, or you crammed everything onto one box and hope nothing collides. Backups? You set them up once. You've never tested a restore.

## One server, all your projects, everything handled

Bring a fresh Debian VPS. Point your projects at it. Go back to building things.

boxmunge turns a single server into a managed home for all your web projects. Each project gets its own Docker Compose setup, its own domain, its own backups — but they share the same box, the same automatic TLS, the same security hardening. You don't configure any of that. It's just there.

And here's what makes it feel like 2026: **your AI agent can run the whole thing.** Every boxmunge command works over SSH, so the same agent that helps you write code can deploy it, check on it, back it up, and restore it. You don't need to learn boxmunge. You don't need to learn Docker networking or Caddy configuration or UFW rules. You build your web project, your agent handles the rest.

That's the real promise — not just "easy hosting," but one less tool you have to carry in your head.

### What you get

- **All your projects on one VPS** — each isolated in Docker Compose, sharing the server
- **Automatic HTTPS** — Caddy + Let's Encrypt, zero configuration
- **Encrypted backups that actually restore** — mandatory restore commands, tested by a self-test that proves it works
- **Zero-downtime deploys** — stage, verify, promote
- **Security hardening out of the box** — firewall, intrusion detection, kernel hardening, automatic security updates
- **AI-native operations** — every command works over SSH and via MCP, designed for agents from day one

## Getting started

### 1. Set up your server

You need a fresh Debian 13 VPS with a public IP. Point your domain at it, then:

```bash
pip install boxmunge
boxmunge server-setup you@your-server.example.com --email you@example.com
```

That's it. boxmunge SSHes in, installs everything, hardens the OS, and sets up the reverse proxy. Takes a few minutes.

### 2. Ship a project

Add a `manifest.yml` to your project — it tells boxmunge what you're running and how to back it up. Or better yet, get your AI agent to do it for you.

```yaml
project: myapp
source: bundle
hosts:
  - myapp.example.com
services:
  web:
    port: 3000
    routes:
      - path: /
backup:
  type: postgres
  dump_command: "pg_dump -U myuser mydb"
  restore_command: "psql -U myuser mydb"
```

Then bundle, upload, and deploy:

```bash
boxmunge stage myapp        # bundle, upload, start staging
boxmunge promote myapp      # swap staging into production
```

Your project is live at `https://myapp.example.com` with TLS, reverse proxy, and backups configured.

### 3. Let your agent take over

Add boxmunge to your AI agent's MCP configuration:

```json
{
  "mcpServers": {
    "boxmunge": {
      "command": "boxmunge",
      "args": ["mcp-serve"]
    }
  }
}
```

The local CLI reads your project's `.boxmunge` config to find the right server automatically — no hardcoded hosts, no risk of deploying to the wrong box. Now "deploy it" is a conversation, not a context switch.

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

- [Architecture](docs/on-server/ARCHITECTURE.md) — system design and components
- [Operations](docs/on-server/OPERATIONS.md) — step-by-step guides
- [Project Conventions](docs/on-server/PROJECT_CONVENTIONS.md) — manifest format
- [Trust Model](docs/on-server/TRUST_MODEL.md) — security model and boundaries
- [Contributing](CONTRIBUTING.md) — how to contribute
- [Security Policy](SECURITY.md) — reporting vulnerabilities
- [Code of Conduct](CODE_OF_CONDUCT.md)

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
