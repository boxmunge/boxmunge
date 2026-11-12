# Platform upgrades, for agents

## TL;DR

1. Run `upgrade-howto`. It prints what to change on the box and in each project, before and
   after the upgrade. Bring your projects up to date with it, and deploy them.
2. Then do what the person asked:
   - **"Get ready for an upgrade":** stop, and tell the person the upgrade command the guide
     ends with (`upgrade --target X.Y.Z`).
   - **"Prepare, then do it":** run `upgrade-check --version X.Y.Z`, and run
     `upgrade --target X.Y.Z` only if the result is **PASS**.
3. Not PASS: **do not upgrade.** Report the result to the person, per project. **Never
   force:** that is the operator's decision (`force-target`), not yours.

## upgrade-howto [--version X.Y.Z] [--json]

The guide for an upgrade to the newest release, or to the one you name. It is composed on
the box from the release's own upgrade notes, which the box verifies against the release's
signature first; nothing about your projects is sent anywhere. Its sections: the box, then
each project before the upgrade (a checklist per file: `manifest.yml`, `compose.yml`,
`Dockerfile`), each project after it, the box after it, then base-image advice and the next
steps. An up-to-date box is told so. A box below the upgrade floor is told which release to
install by hand first.

Exit 0 a guide was printed, 1 the notes could not be fetched or verified (the error says
why), 2 usage.

## upgrade-check [--version X.Y.Z] [--json]

Runs the target release's own readiness check against this box and every project, as root
through the upgrade shim: the release is downloaded and verified, its prerequisites are run,
and its readiness check and upgrade pre-flight run against the live box, confined so they can
change nothing. It takes several minutes, and a check starts at least 10 minutes after the
last one ended.

| Result | Meaning | What you do |
|---|---|---|
| PASS | Prerequisites met, nothing blocks, the pre-flight passed | Upgrade if the person asked you to |
| BLOCKED | A prerequisite is not met (projects are then not checked), a finding blocks, or the pre-flight refused | Fix what you can, deploy, check again; report the rest |
| CAN'T VERIFY | The check could not run or finish: the last check ended less than 10 minutes ago, an upgrade or probation is in progress, a download failed, a time limit | Follow the reason (usually: wait, then run it again). Never read it as a pass |

Each finding reads `[block|todo, before|after] <id>: <message>` with a `Fix:` line. `block`
stops the upgrade; `todo` is work for that project's next deploy; `before`/`after` is when, in
relation to the box upgrade. Every project is listed, passing ones too.

Exit 0 PASS, 1 BLOCKED or CAN'T VERIFY, 2 usage, or nothing to check (the box runs the
newest release, or the one you named).

## The box enforces it

An upgrade that crosses a breaking release runs the same readiness check first, and refuses
unless it passes; nothing is changed or blocklisted. Only the operator's `force-target`
skips the check.

## When version checks are off

With `version_check.enabled: false` the box asks nobody which release is newest, so both
commands need the release: `upgrade-howto --version X.Y.Z`. Releases are listed at
https://github.com/boxmunge/boxmunge/releases.

## MCP and JSON

The MCP tools `upgrade_howto` and `upgrade_check` take `version` and `as_json`. An
`upgrade_check` call can block for as long as 40 minutes on a slow box, when `upgrade-check`
stops waiting and says CAN'T VERIFY. If your client times out first, run `upgrade-check` in
the deploy shell over SSH instead. Retrying less than 10 minutes after the last check ended
is refused (CAN'T VERIFY, naming the time to retry from).

- `upgrade-howto --json`: `{"guide": 1, "status": "guide|below_floor|up_to_date",
  "installed", "target", "box_before", "project_before", "project_after", "box_after",
  "no_action", "text"}`; `text` is the printed guide.
- `upgrade-check --json`: `{"check": 1, "result": "pass|blocked|cant_verify", "stage",
  "reasons", "prerequisites", "readiness", "dry_run", ...}`. `readiness` holds `box` and
  `projects[].findings`. Stage `shim` means the upgrade shim gave no usable verdict.
