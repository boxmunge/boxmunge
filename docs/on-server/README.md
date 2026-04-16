# boxmunge

A minimalist, agent-friendly VPS hosting framework for multiple Docker Compose web projects with automatic HTTPS.

---

## Quick Reference

```
help                 see all commands
agent-help <topic>   AI agent documentation
status               dashboard of all projects
list-projects        list registered projects
doctor               verify host health

inbox                list uploaded bundles
inbox clean          remove old bundles
stage <project>      deploy to staging environment
promote <project>    promote staging to production
unstage <project>    tear down staging without promoting
deploy <project>     deploy directly to production

diff <project>       preview changes before deploying
add-git-project      register a git-based project
secrets              manage project and host secrets

check <project>      run health checks
logs <project>       view container logs
backup <project>     run encrypted backup
validate <project>   validate project config
```

---

## How It Works

- Projects are deployed via bundles (scp upload) or git repos
- Caddy runs in Docker as the reverse proxy, handling automatic HTTPS via Let's Encrypt
- `boxmunge` reads project manifests to generate Caddy config and orchestrate deployments
- A staging environment lets you verify changes at `staging.<hostname>` before promoting to production
- Secrets are managed via the CLI (`secrets`), not by editing files
- Backups are encrypted (age) and restore-tested before being considered valid
- Health checks run on a schedule and send alerts via Pushover on failure
- The host applies unattended security patches automatically

---

## Documentation

Access documentation via `agent-help`:

| Topic | Command |
|---|---|
| System architecture | `agent-help architecture` |
| Operations guide | `agent-help operations` |
| Project conventions | `agent-help conventions` |
| Agent rules | `agent-help rules` |
