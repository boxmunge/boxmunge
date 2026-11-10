# Changelog

The `boxmunge` client on PyPI. It versions independently of the server
(`boxmunge-server`, released on GitHub); each release is tagged `cli-vX.Y.Z`.
The client works with boxmunge-server 0.10.0 or newer; a feature that needs a
newer server says which, and the client refuses it on an older server before
anything is sent.

## 0.3.0

Deploying without an upload:

- `prod-deploy --redeploy` deploys the release already installed again, as
  strictly checked as a new deploy, and uploads nothing. Needs
  boxmunge-server 0.11.4, which refuses a plain `prod-deploy` with no new
  bundle and names this flag.
- `prod-deploy --ref REF` deploys a release the server already has (a bundle
  in its inbox, or the open install an interrupted deploy left) without
  uploading the working tree.
- `prod-deploy --abandon` undoes an interrupted install whose pre-deploy hook
  has not run. It uploads nothing. Needs boxmunge-server 0.11.0.

New flags the server's refusals name:

- `prod-deploy --accept-stale-kev` lets a CVE-quarantined project's fix
  through when the server has no usable CISA KEV catalog. Needs
  boxmunge-server 0.11.5.
- `--no-pull` on `stage`, `prod-deploy` and `promote` builds from the base
  images in the server's image store. Needs boxmunge-server 0.11.4.
- `logs --staging` shows staging's logs. Needs boxmunge-server 0.11.4.

Secrets and confirmations:

- `secrets set KEY` asks for the value without echo at a terminal, or reads
  it from standard input (`pass show myapp/token | boxmunge secrets set
  API_TOKEN`): one line of UTF-8 text, at most 64 KiB, its trailing newline
  dropped, and a second line refused rather than dropped. The value goes to
  the server on ssh's standard input, never in a command line or your shell
  history. Needs boxmunge-server 0.11.5.
- Only the command that needs it reads standard input. The handshake that
  runs first, and every ssh and scp call that sends nothing, get none, so
  they cannot swallow input meant for the command (a piped secret, an MCP
  host's first message). `remote COMMAND` passes standard input on to the
  server command.
- `rollback` and the server commands that ask before acting (`pause`,
  `resume`, `recover`, `restore`, `inbox clean`, `project-delete`) show the
  server's plan and ask at a terminal. When standard input is not a terminal
  (a script, CI) they are refused before anything is sent unless `--yes` is
  given.

Server setup and bundles:

- `server-setup` accepts arm64 (aarch64) servers.
- `server-setup` brackets a literal IPv6 target for scp, asks the host key
  scan for fewer key types and explains an empty scan. On a server whose
  earlier install could not build its boxmunge-system container, it names the
  recovery instead of saying boxmunge is already installed.
- `bundle` keeps a comment on the manifest's `id:` line when it fills the id
  in.
- The scaffold's `project.env` points at `boxmunge secrets set KEY`, which
  keeps the value out of shell history, instead of `ssh ... KEY=value`.

## 0.2.0

First PyPI release: verified `server-setup` (cosign and host-key checks), safe
bundles, a scaffold that deploys, strict argument parsing, and `scp -O`
uploads.
