# boxmunge Agent Rules

You are an AI agent connected to a boxmunge-managed VPS via the `deploy` user.

The deploy shell is a **restricted shell** that dispatches commands directly -- no `boxmunge` prefix needed. There are no other commands available -- no `ls`, `cat`, `cd`, `docker`, `sudo`, or any shell utilities. The boxmunge CLI is your complete interface to this server.

---

## Getting Oriented

Run these commands in order:

1. `help` -- see all available commands (`help <command>` shows one command's usage; it never runs the command)
2. `status` -- check the current state of all projects
3. `agent-help <topic>` -- read documentation (architecture, operations, conventions, rules)

**Before you write or change a Dockerfile, read `agent-help images`.** Use the smallest official
image for your stack, pinned by digest, with a multi-stage build. Every OS package in the image can
trigger a CVE quarantine, including packages your app never uses.

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
| Set a project secret | `secrets set <project> KEY=value` |
| Set a host-level secret | `secrets set --host KEY=value` |
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
2. Upload: `scp -O -P 922 myapp.tar.gz deploy@<host>:`
3. Verify arrival: `inbox`
4. Stage: `stage myapp`
5. Verify staging works, then promote: `promote myapp`

Or skip staging: `prod-deploy myapp`

### Managing secrets

Set secrets before deploying so they are available to containers:

```
secrets set myapp DATABASE_URL=postgres://...
secrets set myapp SECRET_KEY=supersecretvalue
secrets list myapp
```

Host-level secrets (shared across all projects):

```
secrets set --host PUSHOVER_TOKEN=abc123
```

---

## What Requires Confirmation

These commands prompt for confirmation before executing. Use `--yes` only when you are certain the operation is correct and intentional:

- `rollback <project>` -- puts back the previous release's code and its pre-deploy data snapshot (refuses, with the reason, if either is unavailable)
- `restore <project>` -- restores from a backup
- `project-delete <project>` -- destructively deletes a project (containers, files including local backups, registry entry); off-site backup copies are kept
- `pause <project>` -- takes the site offline with a maintenance page
- `resume <project> --skip-security-checks` -- DANGEROUS: brings up potentially vulnerable images without pulling fresh

Do not pass `--yes` reflexively. Confirm the target project and the effect before proceeding.

### Flags are strict

- `help <command>` or `<command> --help` shows a command's usage. Neither runs the command.
- A flag a command does not implement is an error (exit 2) and nothing runs. Read the usage
  rather than guessing flags.
- `--dry-run` exists only on `prod-deploy`, `stage`, `promote`, `unstage` and `upgrade`
  (and the operator-only `container-update`). Other commands, including `project-delete`, `rollback`, `restore` and
  `pause`, reject it. There is no way to preview those; confirm the target before running them.

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
- Use `stage` + `promote` instead of `prod-deploy` when you want to verify first
- Run `validate <project>` before deploying -- it catches config errors early
- Run `doctor` if anything seems wrong or unexpected
- Read error messages carefully -- boxmunge gives clear, actionable errors; do not skip them
- Check `status` before and after making changes
- Do not retry a failed operation blindly -- understand why it failed first
- If a deploy says its install was left open, take one of the ways out it prints: run it again, `prod-deploy <project> --abandon` (before its pre-deploy hook ran), `rollback <project>` (after), or deploy a fix. Nothing else starts the project until then
- Set secrets before the first deploy so containers start with the right environment
- If asked about container security or you are about to relax a `security:` setting, run `security <project>` first to see the current effective posture, and read `agent-help security` for the full model
- If a CVE alert arrives (Pushover or otherwise), or you see `QUARANTINED` / `STILL_RUNNING_AT_RISK` / expired-suppression in `security` output, follow `agent-help cve-incident` end to end. Don't suppress without a concrete exploitability reason; don't resume a project without first re-scanning to confirm no quarantine-level findings remain.

---

## Deployment Workflow

### New project from bundle

1. `inbox` -- confirm bundle is present
2. `secrets set <project> KEY=value` -- set required secrets
3. `stage <project>` -- deploy to staging
4. Verify the staging site at `https://staging.<host>` (stage prints it)
5. `promote <project>` -- go live

### New project from git

1. `add-git-project <name> <repo-url> [--ref REF]` -- register the project
2. `secrets set <project> KEY=value` -- set required secrets
3. `stage <project>` -- deploy to staging
4. Verify the staging site at `https://staging.<host>` (stage prints it)
5. `promote <project>` -- go live

### Updating an existing project

1. `inbox` -- confirm new bundle arrived (or use git)
2. `diff <project>` -- preview changes
3. `stage <project>` -- stage the update
4. Verify the staging site at `https://staging.<host>` (stage prints it)
5. `promote <project>` -- promote to production

---

## When In Doubt

Run `doctor` and `status`.

If you are still unsure what to do, stop and ask the human operator. It is always safer to pause than to take an action you cannot confidently justify.

If a task requires filesystem access, Docker commands, or system administration, tell the operator it requires the **supervisor** user.
