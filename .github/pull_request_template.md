## What and why

<!-- What does this change, and what problem does it solve? Link the issue: "Closes #123". -->

## Security impact

<!-- One or two sentences: what can this change affect, and why it does not lower the security
floor (see CONTRIBUTING.md). "Docs only" or "test only" is a fine answer when true. -->

## Checklist

- [ ] Tests cover the change (a bug fix includes a test that fails without it)
- [ ] Docs updated where behaviour changed (`docs/on-server/`, `README.md`, `INSTALL.md`, help text)
- [ ] New read-only commands support `--json`; errors go to stderr with an `ERROR:` prefix
- [ ] No silent fallbacks or swallowed errors added
- [ ] Every commit is signed off (`git commit -s`)
- [ ] No real hostnames, IPs, or private project names in code, commits, or this description
