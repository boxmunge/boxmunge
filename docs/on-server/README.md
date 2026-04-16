# boxmunge

A minimalist, agent-friendly VPS hosting framework for multiple Docker Compose web projects with automatic HTTPS.

---

## Quick Reference

```
boxmunge help                 see all commands
boxmunge agent-help <topic>   AI agent documentation
boxmunge status               dashboard of all projects
boxmunge list-projects        list registered projects
boxmunge doctor               verify host health

boxmunge inbox                list uploaded bundles
boxmunge inbox clean          remove old bundles
boxmunge stage <project>      deploy to staging environment
boxmunge promote <project>    promote staging to production
boxmunge unstage <project>    tear down staging without promoting
boxmunge deploy <project>     deploy directly to production

boxmunge diff <project>       preview changes before deploying
boxmunge add-git-project      register a git-based project
boxmunge secrets              manage project and host secrets

boxmunge check <project>      run health checks
boxmunge logs <project>       view container logs
boxmunge backup <project>     run encrypted backup
boxmunge validate <project>   validate project config
```

---

## How It Works

- Projects are deployed via bundles (scp upload) or git repos
- Caddy runs in Docker as the reverse proxy, handling automatic HTTPS via Let's Encrypt
- `boxmunge` reads project manifests to generate Caddy config and orchestrate deployments
- A staging environment lets you verify changes at `staging.<hostname>` before promoting to production
- Secrets are managed via the CLI (`boxmunge secrets`), not by editing files
- Backups are encrypted (age) and restore-tested before being considered valid
- Health checks run on a schedule and send alerts via Pushover on failure
- The host applies unattended security patches automatically

---

## Documentation

Access documentation via `agent-help`:

| Topic | Command |
|---|---|
| System architecture | `boxmunge agent-help architecture` |
| Operations guide | `boxmunge agent-help operations` |
| Project conventions | `boxmunge agent-help conventions` |
| Agent rules | `boxmunge agent-help rules` |
