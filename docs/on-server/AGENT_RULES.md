# boxmunge Agent Rules

You are an AI agent connected to a boxmunge-managed VPS via the `deploy` user.

The deploy shell is a **restricted shell** that dispatches commands directly -- no `boxmunge` prefix needed. There are no other commands available -- no `ls`, `cat`, `cd`, `docker`, `sudo`, or any shell utilities. The boxmunge CLI is your complete interface to this server.

---

## Getting Oriented

Run these commands in order:

1. `help` -- see all available commands
2. `status` -- check the current state of all projects
3. `agent-help <topic>` -- read documentation (architecture, operations, conventions, rules)

---

## What You Can Do

These operations are safe to run without human confirmation:

| Goal | Command |
|---|---|
| List uploaded bundles | `inbox` |
| Stage a project for verification | `stage <project>` |
| Promote staging to production | `promote <project>` |
| Abandon staging | `unstage <project>` |
| Deploy directly to production | `prod-deploy <project>` |
| Register a git-based project | `add-git-project <name> <repo-url>` |
| Preview changes before deploying | `diff <project>` |
| Set a project secret | `secrets set <project> KEY value` |
| Set a host-level secret | `secrets set --host KEY value` |
| List secrets | `secrets list <project>` |
| Check server/project health | `status` or `check <project>` |
| Tail container logs | `logs <project>` |
| Query ops audit log | `log --tail 50` |
| Validate a project config | `validate <project>` |
| Run a backup | `backup <project>` |
| Run diagnostics | `doctor` |
| Clean up old bundles | `inbox clean` |
| Read documentation | `agent-help <topic>` |
| Pause a project (planned maintenance) | `pause <project>` |
| Resume a paused project (pulls latest images) | `resume <project>` |
| Show effective container security posture | `security <project> [--json]` |
| Audit overall platform health | `health` |
| Show server boxmunge version | `version` |
| List registered project names | `project-list` |
| Health-check every project | `check-all` (state-mutating; use `check-all --read-only` for pure introspection) |
| Compatibility info for client handshake | `handshake` |

Several commands accept a `--json` flag for machine-readable output, useful when an agent needs to parse rather than render: `check --json`, `validate --json`, `inbox --json`, `project-list --json`, plus `status --json`, `health --json`, `security <project> --json`, and `log --json`.

### Deploying a project (standard workflow)

1. Build a bundle locally: `boxmunge bundle ./myapp`
2. Upload: `scp -P 922 myapp.tar.gz deploy@<host>:`
3. Verify arrival: `inbox`
4. Stage: `stage myapp`
5. Verify staging works, then promote: `promote myapp`

Or skip staging: `prod-deploy myapp`

### Managing secrets

Set secrets before deploying so they are available to containers:

```
secrets set myapp DATABASE_URL postgres://...
secrets set myapp SECRET_KEY supersecretvalue
secrets list myapp
```

Host-level secrets (shared across all projects):

```
secrets set --host PUSHOVER_TOKEN abc123
```

---

## What Requires Confirmation

These commands prompt for confirmation before executing. Use `--yes` only when you are certain the operation is correct and intentional:

- `rollback <project>` -- rolls back to the previous deployment
- `restore <project>` -- restores from a backup
- `project-delete <project>` -- destructively deletes a project (containers, files, registry entry)
- `pause <project>` -- takes the site offline with a maintenance page
- `resume <project> --skip-security-checks` -- DANGEROUS: brings up potentially vulnerable images without pulling fresh

Do not pass `--yes` reflexively. Confirm the target project and the effect before proceeding.

---

## What You Cannot Do

The restricted shell does not allow:

- Browsing the filesystem (`ls`, `cat`, `cd`, `find`)
- Running Docker commands directly (`docker`, `docker compose`)
- Editing files on disk (`nano`, `vim`, `sed`)
- Running commands as root (`sudo`)
- Accessing documentation files directly (use `agent-help <topic>` instead)
- Any command that is not a boxmunge subcommand

If a task requires any of the above, it requires the **supervisor** user. Note this in your response and let the human operator handle it.

---

## Safe Practices

- Use `diff <project>` before deploying to preview changes
- Use `stage` + `promote` instead of `deploy` when you want to verify first
- Run `validate <project>` before deploying -- it catches config errors early
- Run `doctor` if anything seems wrong or unexpected
- Read error messages carefully -- boxmunge gives clear, actionable errors; do not skip them
- Check `status` before and after making changes
- Do not retry a failed operation blindly -- understand why it failed first
- Set secrets before the first deploy so containers start with the right environment
- If asked about container security or you are about to relax a `security:` setting, run `security <project>` first to see the current effective posture, and read `agent-help security` for the full model

---

## Deployment Workflow

### New project from bundle

1. `inbox` -- confirm bundle is present
2. `secrets set <project> KEY value` -- set required secrets
3. `stage <project>` -- deploy to staging
4. `check <project>` -- verify health
5. `promote <project>` -- go live

### New project from git

1. `add-git-project <name> <repo-url> [--ref REF]` -- register the project
2. `secrets set <project> KEY value` -- set required secrets
3. `stage <project>` -- deploy to staging
4. `check <project>` -- verify health
5. `promote <project>` -- go live

### Updating an existing project

1. `inbox` -- confirm new bundle arrived (or use git)
2. `diff <project>` -- preview changes
3. `stage <project>` -- stage the update
4. `check <project>` -- verify health
5. `promote <project>` -- promote to production

---

## When In Doubt

Run `doctor` and `status`.

If you are still unsure what to do, stop and ask the human operator. It is always safer to pause than to take an action you cannot confidently justify.

If a task requires filesystem access, Docker commands, or system administration, tell the operator it requires the **supervisor** user.
