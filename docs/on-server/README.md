# boxmunge

A minimalist, agent-friendly VPS hosting framework for multiple Docker Compose web projects with automatic HTTPS.

---

## Quick Reference

```
help                 see all commands
agent-help <topic>   AI agent documentation
version              show installed boxmunge version
status               dashboard of all projects
doctor               verify host health
health               run platform-wide health checks

inbox                list uploaded bundles
inbox clean          remove old bundles
stage <project>      stage alongside production for verification
promote <project>    promote staging to production
unstage <project>    tear down staging without promoting
prod-deploy <p>      deploy directly to production
rollback <p>         restore previous deployment
pause <project>      take offline with maintenance page
resume <project>     bring back online (pulls latest images first)
project-delete <p>   destructive removal (containers + files + registry)

diff <project>       preview changes before deploying
add-git-project      register a git-based project
project-add <name>   register a project name in the allowlist
project-list         list registered project names
secrets              manage project and host secrets

check <project>      run health checks
log [filters]        query structured ops audit log
logs <project>       tail container/host logs
backup <project>     run encrypted backup
restore <project>    restore from a backup snapshot
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
