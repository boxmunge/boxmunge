# __PROJECT_NAME__

Managed by [boxmunge](https://github.com/boxmunge/boxmunge).

## Key Files

| File | Purpose |
|------|---------|
| `manifest.yml` | Project manifest: services, hosts, backup, deploy config |
| `compose.yml` | Docker Compose service definitions |
| `project.env` | Non-secret environment variables, kept on the server beside the clone (credentials go in `secrets.env` through `boxmunge secrets set`) |
| `boxmunge-scripts/smoke.sh` | Smoke test, run inside the service's container after each deploy and by the health monitor |

## Setup

1. Edit `manifest.yml` — set `repo`, `hosts`, and configure any services you need.
2. Copy the env file and fill in non-secret values (set credentials with
   `boxmunge secrets set __PROJECT_NAME__ KEY=value`):
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
   boxmunge prod-deploy __PROJECT_NAME__
   ```

## Common Commands

```bash
# Validate manifest and compose config
boxmunge validate __PROJECT_NAME__

# Deploy (fetch the ref, build, run the smoke test)
boxmunge prod-deploy __PROJECT_NAME__

# Check health / run smoke test manually
boxmunge check __PROJECT_NAME__

# Tail service logs
boxmunge logs __PROJECT_NAME__

# Trigger a backup
boxmunge backup __PROJECT_NAME__
```
