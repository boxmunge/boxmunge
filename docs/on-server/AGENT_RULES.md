# boxmunge Agent Rules

You are an AI agent connected to a boxmunge-managed VPS via the `deploy` user.

The deploy shell is a **restricted shell**. You can only run `boxmunge` commands. There are no other commands available -- no `ls`, `cat`, `cd`, `docker`, `sudo`, or any shell utilities. The boxmunge CLI is your complete interface to this server.

---

## Getting Oriented

Run these commands in order:

1. `boxmunge help` -- see all available commands
2. `boxmunge status` -- check the current state of the server
3. `boxmunge list-projects` -- see all managed projects
4. `boxmunge agent-help <topic>` -- read documentation (architecture, operations, conventions, rules)

---

## What You Can Do

These operations are safe to run without human confirmation:

| Goal | Command |
|---|---|
| List uploaded bundles | `boxmunge inbox` |
| Stage a project for verification | `boxmunge stage <project>` |
| Promote staging to production | `boxmunge promote <project>` |
| Abandon staging | `boxmunge unstage <project>` |
| Deploy directly to production | `boxmunge deploy <project>` |
| Register a git-based project | `boxmunge add-git-project <name> --repo <url>` |
| Preview changes before deploying | `boxmunge diff <project>` |
| Set a project secret | `boxmunge secrets set <project> KEY value` |
| Set a host-level secret | `boxmunge secrets set --host KEY value` |
| List secrets | `boxmunge secrets list <project>` |
| Check server/project health | `boxmunge status` or `boxmunge check <project>` |
| View application logs | `boxmunge logs <project>` |
| Validate a project config | `boxmunge validate <project>` |
| Run a backup | `boxmunge backup <project>` |
| Run diagnostics | `boxmunge doctor` |
| Clean up old bundles | `boxmunge inbox clean` |
| Read documentation | `boxmunge agent-help <topic>` |

### Deploying a project (standard workflow)

1. Build a bundle locally: `boxmunge bundle ./myapp`
2. Upload: `scp -P 922 myapp.tar.gz deploy@<host>:`
3. Verify arrival: `boxmunge inbox`
4. Stage: `boxmunge stage myapp`
5. Verify staging works, then promote: `boxmunge promote myapp`

Or skip staging: `boxmunge deploy myapp`

### Managing secrets

Set secrets before deploying so they are available to containers:

```
boxmunge secrets set myapp DATABASE_URL postgres://...
boxmunge secrets set myapp SECRET_KEY supersecretvalue
boxmunge secrets list myapp
```

Host-level secrets (shared across all projects):

```
boxmunge secrets set --host PUSHOVER_TOKEN abc123
```

---

## What Requires Confirmation

These commands prompt for confirmation before executing. Use `--yes` only when you are certain the operation is correct and intentional:

- `boxmunge rollback <project>` -- rolls back to the previous deployment
- `boxmunge restore <project>` -- restores from a backup
- `boxmunge remove-project <project>` -- removes a project entirely

Do not pass `--yes` reflexively. Confirm the target project and the effect before proceeding.

---

## What You Cannot Do

The restricted shell does not allow:

- Browsing the filesystem (`ls`, `cat`, `cd`, `find`)
- Running Docker commands directly (`docker`, `docker compose`)
- Editing files on disk (`nano`, `vim`, `sed`)
- Running commands as root (`sudo`)
- Accessing documentation files directly (use `boxmunge agent-help <topic>` instead)
- Any shell command that is not a `boxmunge` subcommand

If a task requires any of the above, it requires the **supervisor** user. Note this in your response and let the human operator handle it.

---

## Safe Practices

- Use `boxmunge diff <project>` before deploying to preview changes
- Use `boxmunge stage` + `boxmunge promote` instead of `boxmunge deploy` when you want to verify first
- Run `boxmunge validate <project>` before deploying -- it catches config errors early
- Run `boxmunge doctor` if anything seems wrong or unexpected
- Read error messages carefully -- boxmunge gives clear, actionable errors; do not skip them
- Check `boxmunge status` before and after making changes
- Do not retry a failed operation blindly -- understand why it failed first
- Set secrets before the first deploy so containers start with the right environment

---

## Deployment Workflow

### New project from bundle

1. `boxmunge inbox` -- confirm bundle is present
2. `boxmunge secrets set <project> KEY value` -- set required secrets
3. `boxmunge stage <project>` -- deploy to staging
4. `boxmunge check <project>` -- verify health
5. `boxmunge promote <project>` -- go live

### New project from git

1. `boxmunge add-git-project <name> --repo <url>` -- register the project
2. `boxmunge secrets set <project> KEY value` -- set required secrets
3. `boxmunge stage <project>` -- deploy to staging
4. `boxmunge check <project>` -- verify health
5. `boxmunge promote <project>` -- go live

### Updating an existing project

1. `boxmunge inbox` -- confirm new bundle arrived (or use git)
2. `boxmunge diff <project>` -- preview changes
3. `boxmunge stage <project>` -- stage the update
4. `boxmunge check <project>` -- verify health
5. `boxmunge promote <project>` -- promote to production

---

## When In Doubt

Run `boxmunge doctor` and `boxmunge status`.

If you are still unsure what to do, stop and ask the human operator. It is always safer to pause than to take an action you cannot confidently justify.

If a task requires filesystem access, Docker commands, or system administration, tell the operator it requires the **supervisor** user.
