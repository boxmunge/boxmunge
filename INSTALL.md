# boxmunge — Installing the client

boxmunge has two parts:

- **The server** (`boxmunge-server`) runs on your VPS. It is installed from signed GitHub releases,
  either by `boxmunge server-setup` (below) or by running the release's `boxmunge-install.sh` on the
  server as described in the [README](README.md). It is not on PyPI.
- **The client** (`boxmunge`) runs on your machine. It scaffolds and bundles projects, uploads them,
  drives the server over SSH, and provides the MCP proxy for agents. It is on PyPI.

## Install the client

Python 3.10 or newer, and OpenSSH 8.7 or newer (uploads use `scp -O`):

```bash
pipx install boxmunge        # recommended: an isolated install on your PATH
# or
python3 -m pip install --user boxmunge
```

Check it:

```bash
boxmunge --version
boxmunge --help
```

`boxmunge server-setup` also needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
on your machine: it verifies the release's signature locally before installing anything on the
server, and refuses to continue without it.

## Set up a server and ship a project

```bash
boxmunge server-setup root@box.example.com --email you@example.com
cd myapp
boxmunge init --server box.example.com --host myapp.example.com
boxmunge remote project-add myapp   # once, registers the project on the server
boxmunge stage && boxmunge promote
```

See [cli/README.md](cli/README.md) for every command, the `.boxmunge` file, what goes into a
bundle, and MCP configuration.

## Upgrade

```bash
pipx upgrade boxmunge        # or: python3 -m pip install --user --upgrade boxmunge
```

The client and server version independently. If the server needs a newer client, every server
command stops with a message telling you to upgrade.

## Uninstall

```bash
pipx uninstall boxmunge      # or: python3 -m pip uninstall boxmunge
```
