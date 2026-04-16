# boxmunge — Local Installation

The `boxmunge` CLI works in two contexts:

- **On the server** — full command set (deploy, stage, secrets, etc.). Installed by `init-host.sh`.
- **Locally** — `boxmunge bundle` and `boxmunge bundle --validate` only. Used to build and validate bundles before uploading.

## Local install (macOS / Linux)

One-time setup. Creates an isolated venv and symlinks the `boxmunge` command to `~/bin/`.

```bash
# From the boxmunge repo directory:
./scripts/install-local.sh
```

This installs only the core dependency (PyYAML). The TUI (`textual`) is not installed.

## Upgrading

After pulling new changes:

```bash
./scripts/install-local.sh
```

Same script — it reinstalls into the existing venv.

## Manual install

If you prefer not to use the script:

```bash
python3 -m venv ~/.local/share/boxmunge-venv
~/.local/share/boxmunge-venv/bin/pip install /path/to/boxmunge
ln -sf ~/.local/share/boxmunge-venv/bin/boxmunge ~/bin/boxmunge
```

## Verify

```bash
boxmunge help
boxmunge bundle --validate ./my-project
```

## Uninstall

```bash
rm ~/bin/boxmunge
rm -rf ~/.local/share/boxmunge-venv
```
