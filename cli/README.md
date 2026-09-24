# boxmunge

The local CLI for [boxmunge](https://github.com/boxmunge/boxmunge) — deploy your
side projects to a single VPS, without carrying Docker networking, Caddy config
and firewall rules around in your head.

This package is the **client**. It bundles a project, uploads it, and drives the
server over SSH. The server component (`boxmunge-server`) is installed on your
VPS from GitHub releases, not from PyPI.

## Install

```
pip install boxmunge
```

## Use

```
boxmunge init --server my.vps.example     # scaffold a project + .boxmunge config
boxmunge bundle ./myapp                   # build a deployable bundle
boxmunge stage                            # bundle, upload, stage on the server
boxmunge promote                          # promote staging to production
boxmunge status                           # project status on the server
boxmunge logs                             # project logs from the server
```

`boxmunge server-setup [user@]host` turns a fresh Debian VPS into a boxmunge
server.

## Requirements

- Python 3.10+
- An SSH key on the target server

## Links

- [Source and documentation](https://github.com/boxmunge/boxmunge)
- [Issue tracker](https://github.com/boxmunge/boxmunge/issues)

Licensed under Apache-2.0.
