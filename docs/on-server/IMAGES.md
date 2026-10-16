# Choosing a base image

## TL;DR for agents

- Use the **smallest official image for your stack**: a `-slim` or distroless image. Never a full
  or generic distro image.
- **Pin it by digest** (`FROM image:tag@sha256:...`).
- Use a **multi-stage build**: compilers, package-manager caches, and build headers stay in the
  builder stage.
- When a CVE alert arrives, **first ask whether the package needs to be in the image at all**.
  Slimming the image beats suppressing the finding.

## Why it matters on boxmunge

boxmunge scans every running image and can **quarantine** a project: the site goes to a maintenance
page and its containers stop. Every OS package in your image is something that can be scanned,
flagged, and acted on, whether or not your app ever uses it.

A full `python:3.x` or `node:N` image ships hundreds of packages: compilers, Perl, image libraries,
version-control tools. Each carries its own stream of CVEs. A real outage on boxmunge came from a
Critical CVE in `perl-base`, inside a Python app that never runs Perl. The package was there only
because the base image shipped it.

boxmunge's CVE policy has defences against this (distro triage, a runtime relevance gate), but
they are heuristics. The reliable fix is not shipping the package.

## By stack

| Stack | Runtime base image | Notes |
|---|---|---|
| Python | official `python:3.N-slim` | Build wheels in a builder stage; copy the virtualenv into the slim stage. Distroless Python is smaller still. |
| Node.js | official `node:N-slim` | Run `npm ci --omit=dev` in a builder stage; copy `node_modules` and the app. Distroless Node.js is smaller still. |
| Go, Rust, other static binaries | distroless `static`, or `scratch` | Nothing but your binary and CA certificates. |
| Java / JVM | a JRE image, not a JDK | Build with the JDK in a builder stage. |
| Static site | a small web-server image | Or serve it from a project that already runs one. |

Check the publisher's current tags when you write the Dockerfile; do not copy tags from old
examples.

## Debian-based or Alpine?

Prefer Debian-based slim or distroless images. boxmunge's CVE policy trusts the distribution's own
security triage: a CVE Debian rates as minor or not affecting the package does not take your site
down.

Alpine images are small, but Alpine's vulnerability data carries no distro severity rating. Below
the `paranoid` posture, most Alpine findings are therefore treated as informational. That means
fewer quarantines, but also less protection for anything short of an actively exploited CVE. Alpine
also uses musl rather than glibc, which some Python and Node packages handle poorly. Choose it
deliberately, not by default.

## Multi-stage example (Python)

```dockerfile
FROM python:3.13-slim@sha256:<digest> AS build
WORKDIR /app
RUN python -m venv /venv
COPY requirements.txt .
RUN /venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.13-slim@sha256:<digest>
RUN useradd --uid 10001 --no-create-home app
COPY --from=build /venv /venv
COPY app/ /app/
USER app
CMD ["/venv/bin/python", "-m", "app"]
```

The runtime stage contains the interpreter, your dependencies, and your code. There is no
compiler, no pip cache, and no build headers.

## Pinning and refreshing

Pin by digest so a rebuild cannot silently change what ships. To get the current digest:

```bash
docker buildx imagetools inspect python:3.13-slim
```

Pinning means you choose when to take upstream fixes, so rebuild regularly. `container-update`
refreshes services that use a published `image:` (including ones from `include:` files or
`${VAR:-image}`); with `strategy: rollback_to_previous` an unhealthy update is rolled back to the
exact image that ran before. Services that
`build:` from your Dockerfile only change when you rebuild and redeploy.

## Also remember

- The root filesystem is read-only. Declare writable paths in the manifest (`agent-help
  writable`); do not write into the image at runtime.
- Run as a non-root user.
- If your smoke script needs a tool (`curl`, `wget`), it must exist in the runtime image, or use
  the language runtime instead (`agent-help conventions`).
