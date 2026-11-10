# system/Dockerfile
# boxmunge-system: lightweight container for age + rclone tooling
# Provides blast-radius containment and reproducible tool versions.

# A multi-arch index: BuildKit picks the variant for the host it builds on.
# Dependabot bumps this digest, and only this.
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

# age and rclone are upstream release binaries, one per architecture boxmunge
# supports (amd64, arm64; install.sh refuses any other host). Each download is
# checked against the SHA256 pinned here before it is unpacked. Dependabot
# cannot see these: bump a version and all four of its hashes by hand, in one
# commit, from upstream's signed checksums (rclone: the PGP-signed SHA256SUMS
# of the release; age: the sigsum .proof beside each asset, see SIGSUM.md in
# the age repository). CI builds the image on both architectures.
ARG AGE_VERSION=1.3.2
ARG AGE_SHA256_AMD64=cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10
ARG AGE_SHA256_ARM64=6b8dc4333c53a5a57c9e5834e3a48f92605d7154014cd07269ff3327db5d37f4
ARG RCLONE_VERSION=1.75.2
ARG RCLONE_SHA256_AMD64=349ac8fba6ff65d6247043f1750cdcb518ec5d500ef91463a10d37c0ccdf3702
ARG RCLONE_SHA256_ARM64=7e1e8d69654941b7b7df84ee74c5f7fb09cce7d5496947fb7bf16b55ff427d10
# Set by BuildKit (which `docker compose build` uses) to the architecture
# being built; both upstreams name their assets with the same words.
ARG TARGETARCH

RUN case "${TARGETARCH}" in \
        amd64) age_sha256="${AGE_SHA256_AMD64}" rclone_sha256="${RCLONE_SHA256_AMD64}" ;; \
        arm64) age_sha256="${AGE_SHA256_ARM64}" rclone_sha256="${RCLONE_SHA256_ARM64}" ;; \
        "") echo "TARGETARCH is not set: build with BuildKit (docker compose build, or docker buildx build)" >&2; exit 1 ;; \
        *) echo "boxmunge-system has age and rclone pins for amd64 and arm64 only, not ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && apk add --no-cache \
        ca-certificates \
        curl \
        unzip \
    && curl -fsSL --proto =https --proto-redir =https "https://github.com/FiloSottile/age/releases/download/v${AGE_VERSION}/age-v${AGE_VERSION}-linux-${TARGETARCH}.tar.gz" \
        -o /tmp/age.tar.gz \
    && echo "${age_sha256}  /tmp/age.tar.gz" | sha256sum -c - \
    && tar xzf /tmp/age.tar.gz -C /usr/local/bin --strip-components=1 age/age age/age-keygen \
    && rm /tmp/age.tar.gz \
    && curl -fsSL --proto =https --proto-redir =https "https://downloads.rclone.org/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-linux-${TARGETARCH}.zip" \
        -o /tmp/rclone.zip \
    && echo "${rclone_sha256}  /tmp/rclone.zip" | sha256sum -c - \
    && unzip -q /tmp/rclone.zip -d /tmp \
    && mv "/tmp/rclone-v${RCLONE_VERSION}-linux-${TARGETARCH}/rclone" /usr/local/bin/ \
    && rm -rf /tmp/rclone* \
    && apk del curl unzip \
    && age --version \
    && env -u RCLONE_VERSION rclone version

# Non-root by default. compose.yml runs it as the deploy user's uid:gid
# (set at start time by install.sh), so no uid is baked into the image.
USER 65534:65534

ENTRYPOINT ["sleep", "infinity"]
