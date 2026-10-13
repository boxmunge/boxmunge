# Contributing to boxmunge

Thanks for wanting to help. boxmunge is open source under the Apache License 2.0, and contributions
are welcome: bug reports, fixes, docs, tests, and new capabilities.

This page explains what the project values, how to propose a change, and what a PR needs before it
can merge. For how the code is organised and how to run it, see
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## What boxmunge is for

boxmunge turns one Debian VPS into a safe, managed home for many small web projects, and it is
designed to be operated by an AI agent as much as by a person. People run it on servers that hold
their users' data. That shapes every decision below.

## Principles

These are the tests we apply to every change. Knowing them up front saves you a review round.

### The security floor only rises

boxmunge's defaults are its promise. Every project gets container hardening, encrypted backups,
CVE quarantine, signed upgrades, and a restricted deploy shell without asking for them. Operators
trust that a boxmunge box is safe without configuration.

So a change that **lowers the default security posture** will not be merged as a default, however
convenient it is. That includes:

- weakening container isolation or the restricted shell, or widening what the `deploy` user can do;
- relaxing validation of manifests, compose files, bundles, or names;
- making a security control optional by default, or adding a way to skip it silently;
- adding a network listener, a new principal, or a new path for data to leave the box.

This is not "no". Many of these ideas are good for *some* operators. The way to offer them is as an
**explicit, opt-in choice** that is visible, documented, and audited: a manifest field with a
required `reason`, or a [plugin](#proposing-a-plugin) that an operator chooses to install. If you
are unsure, open an issue first and describe the trade-off. We are glad to help find the opt-in
shape.

### Fail noisily

If an assumption is violated, stop and say so clearly. Do not add fallbacks that quietly carry on,
defaults that paper over a missing value, or `except` blocks that swallow errors. A loud failure
gets fixed. A silent fallback hides the problem until it costs someone their data.

Best-effort paths exist (alert delivery, for example) and that's fine. Make them obviously
best-effort, logged, and documented as such.

### Stay lean

- No backward-compatibility shims. If something is unused, delete it.
- Source files stay under 500 lines; above 650 they must be split along a natural seam. CI enforces
  the 650 hard limit.
- One concern per PR.

### The docs describe what the code does today

Operators and agents read `docs/on-server/` on the box via `agent-help`. If your change alters
behaviour, update the doc in the same PR. A doc that promises something the code doesn't do is a
bug.

### Agents are first-class users

Every command must work non-interactively over SSH. Read-only commands should offer `--json`.
Errors go to stderr, start with `ERROR:`, and say what to do next.

## How to propose a change

**Small fixes** (typos, an obvious bug with a clear fix, a missing test): open a PR directly.

**Anything larger**: open an issue first using the templates, describe the problem and the shape of
the fix, and wait for a maintainer to say it fits. This avoids you spending a weekend on something
that would not merge.

**Security vulnerabilities**: do not open a public issue or PR. Follow [SECURITY.md](SECURITY.md).

## What a PR needs

- **Tests.** New behaviour has tests; bug fixes have a test that fails without the fix. Prefer
  tests that exercise real behaviour over tests that mock the thing being tested.
- **Docs.** Updated in the same PR when behaviour changes (`docs/on-server/`, `README.md`,
  `INSTALL.md`, `agent-help` text).
- **A security-impact note** in the PR description: what the change can affect, and why it does
  not lower the security floor. One sentence is fine for most changes.
- **Green CI.** Lint, unit tests, client tests, Docker integration tests, and the sign-off check.
- **DCO sign-off on every commit** (see below).
- **No private details.** Do not put real server hostnames, IP addresses, project names from your
  own deployments, or log excerpts containing them in commits, issues, or PRs. Use generic
  stand-ins such as `example.com` and `myapp`.

### Paths that need maintainer review

Some paths are security-sensitive and always need review from a maintainer (enforced by
`.github/CODEOWNERS`): the restricted shell and bundle reception, bootstrap and install scripts,
the upgrade shim, CI workflows, the CVE policy engine, the container security overlay and compose
validation, and secrets handling. Changes there are welcome. Expect a slower, more careful review.

## Sign your commits (DCO)

boxmunge uses the [Developer Certificate of Origin](https://developercertificate.org/) (DCO) instead
of a contributor licence agreement. There is nothing to sign. You add a sign-off line to each
commit, which certifies that you wrote the change or otherwise have the right to submit it under the
project's licence.

Add the line automatically with `-s`:

```bash
git commit -s -m "fix(backup): close the temp file before encrypting"
```

That appends a trailer using your configured name and email, which must match the commit author:

```text
Signed-off-by: Your Name <you@example.com>
```

CI checks every commit in a PR. If you forgot, sign off the whole branch and force-push:

```bash
git rebase --signoff main
git push --force-with-lease
```

## Proposing a plugin

Some capabilities belong outside the core, because they add attack surface not every operator
should carry. An on-box web UI is the canonical example. boxmunge supports these as opt-in
**plugins**: separately developed, separately installed, and granted only the capabilities the
operator approves.

The plugin model and its API are being specified now. If you want to build a plugin, open an issue
describing it, and we will point you at the current contract. Plugins can never hold operator-only
powers (security overrides, secret access, platform upgrades), so a plugin cannot lower the
security floor of a box that installs it.

## Development setup

```bash
git clone https://github.com/boxmunge/boxmunge.git
cd boxmunge
python3 -m venv .venv && source .venv/bin/activate
pip install --require-hashes -r requirements.txt
pip install --require-hashes -r requirements-tui.txt
pip install --require-hashes -r requirements-dev.txt
pip install -e . --no-deps
make lint              # ruff
make test              # server unit tests (fast, no Docker)
make test-cli          # client unit tests
make test-integration  # integration tests (needs Docker and age)
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the codebase map, how to add a command, and the
full-system VM test harness.

## Expectations

boxmunge has one maintainer. PRs are reviewed as time allows, and there is no SLA. Not every feature
request will be accepted, because boxmunge is opinionated by design. A "not for core" answer is not
a judgement of the idea, and often the answer is "yes, as a plugin".

Be kind. This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
