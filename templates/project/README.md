# __PROJECT_NAME__

Managed by [boxmunge](https://github.com/YOUR_ORG/boxmunge).

## Key Files

| File | Purpose |
|------|---------|
| `manifest.yml` | Project manifest: services, hosts, backup, deploy config |
| `compose.yml` | Docker Compose service definitions |
| `project.env` | Environment variables (not committed to git) |
| `boxmunge-scripts/smoke.sh` | Health check run after each deploy |

## Setup

1. Edit `manifest.yml` — set `repo`, `hosts`, and configure any services you need.
2. Copy the env file and fill in real values:
   ```
   cp project.env.example project.env
   ```
3. Configure `boxmunge-scripts/smoke.sh` with health checks for your services.
4. Validate the project config:
   ```
   boxmunge validate __PROJECT_NAME__
   ```
5. Deploy:
   ```
   boxmunge deploy __PROJECT_NAME__
   ```

## Common Commands

```bash
# Validate manifest and compose config
boxmunge validate __PROJECT_NAME__

# Deploy (pull latest, run smoke test)
boxmunge deploy __PROJECT_NAME__

# Check health / run smoke test manually
boxmunge check __PROJECT_NAME__

# Tail service logs
boxmunge logs __PROJECT_NAME__

# Trigger a backup
boxmunge backup __PROJECT_NAME__
```
