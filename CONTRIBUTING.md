# Contributing to boxmunge

boxmunge is open source under the Apache License 2.0. Contributions are welcome.

## Expectations

This is a solo-maintained project released for anyone who finds it useful. It's not backed by a company or a team. That means:

- **PRs are reviewed on the maintainer's timeline** — there's no SLA. Be patient.
- **Not every feature request will be accepted** — boxmunge is opinionated by design. If a suggestion doesn't fit the project's direction, that's not a reflection on the quality of the idea.
- **Security reports are prioritised** — see [SECURITY.md](SECURITY.md).

## How to contribute

**Issues:** Please open an issue before starting work on a significant change. Describe what you want to do and why. This avoids wasted effort if the change doesn't fit the project's direction. Use the issue templates — they help.

**Pull requests:** PRs should reference an issue. Keep changes focused — one concern per PR. Include tests for new functionality.

**Bug reports:** Use the bug report template. Include the boxmunge version (`boxmunge --version`), your OS, and steps to reproduce.

**Security vulnerabilities:** Do not open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Development setup

```bash
git clone <repo>
cd boxmunge
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[tui]'
pip install pytest
make test              # Unit tests (fast, no Docker)
make test-integration  # Integration tests (requires Docker + age)
```

## Code standards

- Python 3.10+ with type hints
- Source files under 500 lines
- Tests for all new functionality
- No backwards-compatibility shims — if something is unused, delete it
- Errors should fail noisily — no silent fallbacks that mask problems

## Architecture

See `docs/on-server/ARCHITECTURE.md` for system design. The codebase follows a command-handler pattern: `src/boxmunge/commands/` contains one file per CLI command, `src/boxmunge/` contains shared modules.
