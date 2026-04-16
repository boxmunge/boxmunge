# boxmunge

A minimalist, agent-friendly VPS hosting framework for running multiple Docker Compose projects on a single server.

## What is this?

boxmunge gives you a managed platform layer for your side projects without the overhead of a full PaaS. You get:

- **Multiple projects on one VPS** — each with its own Docker Compose setup, sharing the same server
- **Automatic HTTPS** via Caddy + Let's Encrypt, zero configuration
- **Encrypted backups** with mandatory restore scripts — no write-only backups
- **Zero-downtime deploys** with staging/promote workflow
- **Agent-friendly CLI** — designed for AI agents to manage deployments via SSH
- **Host hardening out of the box** — UFW, CrowdSec, kernel hardening, file integrity monitoring, automatic security updates
- **Self-test command** that proves your backup/restore pipeline actually works

## Who is this for?

Individual developers who want to ship web projects without thinking about infrastructure. You want to say "deploy it" and have everything handled — TLS, reverse proxy, backups, monitoring, security patching.

boxmunge is **not** for multi-tenant hosting, enterprise deployments, or situations requiring granular IAM. It's for the time-constrained solo developer who wants their pet projects and side hustles to go live without having to think about it.

## Quickstart

### 1. Bootstrap a VPS

On a fresh Debian 13 server:

```bash
curl -fsSL https://raw.githubusercontent.com/boxmunge/boxmunge/main/init | sudo bash -s -- \
  --hostname box.example.com \
  --email you@example.com \
  --ssh-key "ssh-ed25519 AAAA..."
```

This installs Docker, Caddy, boxmunge CLI, configures SSH, firewall, backups, and hardening.

### 2. Deploy a project

Create a `manifest.yml` in your project:

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
    smoke: boxmunge-scripts/smoke.sh
backup:
  type: postgres
  dump_command: "pg_dump -U myuser mydb"
  restore_command: "psql -U myuser mydb"
```

Bundle and deploy:

```bash
boxmunge bundle ./myapp
scp -P 922 myapp.tar.gz deploy@box.example.com:
ssh -p 922 deploy@box.example.com deploy myapp
```

### 3. Verify everything works

```bash
ssh -p 922 deploy@box.example.com self-test
ssh -p 922 deploy@box.example.com health
```

## Commands

Server-side commands (run via SSH as the deploy user -- no `boxmunge` prefix needed):

| Command | Description |
|---------|-------------|
| `deploy <project>` | Deploy to production |
| `stage <project>` | Deploy to staging for verification |
| `promote <project>` | Promote staging to production |
| `backup <project>` | Create encrypted backup |
| `restore <project>` | Restore from backup |
| `rollback <project>` | Restore pre-deploy snapshot + redeploy previous version |
| `self-test` | Prove backup/restore works via canary project |
| `health` | Non-destructive platform audit |
| `upgrade` | Update the platform (stash + migrate + restart) |
| `log` | Query structured operational logs |
| `secrets set/get/list/unset` | Manage project secrets |
| `status` | Dashboard of all projects |

## MCP (Model Context Protocol)

boxmunge supports MCP for structured agent access. Add to your Claude Code or Cursor configuration:

```json
{
  "mcpServers": {
    "boxmunge": {
      "command": "ssh",
      "args": ["-p", "922", "deploy@your-box.example.com", "mcp-serve"]
    }
  }
}
```

This gives your agent structured access to all boxmunge commands — deploy, backup, restore, health checks, log queries, and more — over the same SSH connection you already use.

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
