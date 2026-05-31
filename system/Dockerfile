# system/Dockerfile
# boxmunge-system: lightweight container for age + rclone tooling
# Provides blast-radius containment and reproducible tool versions.

FROM alpine:3.21

ARG AGE_VERSION=1.2.1
ARG RCLONE_VERSION=1.68.2
# SHA256 of the upstream binary tarballs. Verified before extraction.
# Bumped together with AGE_VERSION / RCLONE_VERSION via Dependabot or
# manual edit (look up via:  curl -fsSL <url> | sha256sum ).
ARG AGE_SHA256=7df45a6cc87d4da11cc03a539a7470c15b1041ab2b396af088fe9990f7c79d50
ARG RCLONE_SHA256=0e6fa18051e67fc600d803a2dcb10ddedb092247fc6eee61be97f64ec080a13c

RUN apk add --no-cache \
        ca-certificates \
        curl \
        unzip \
    && curl -fsSL "https://github.com/FiloSottile/age/releases/download/v${AGE_VERSION}/age-v${AGE_VERSION}-linux-amd64.tar.gz" \
        -o /tmp/age.tar.gz \
    && echo "${AGE_SHA256}  /tmp/age.tar.gz" | sha256sum -c - \
    && tar xzf /tmp/age.tar.gz -C /usr/local/bin --strip-components=1 age/age age/age-keygen \
    && rm /tmp/age.tar.gz \
    && curl -fsSL "https://downloads.rclone.org/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-linux-amd64.zip" \
        -o /tmp/rclone.zip \
    && echo "${RCLONE_SHA256}  /tmp/rclone.zip" | sha256sum -c - \
    && unzip -q /tmp/rclone.zip -d /tmp \
    && mv "/tmp/rclone-v${RCLONE_VERSION}-linux-amd64/rclone" /usr/local/bin/ \
    && rm -rf /tmp/rclone* \
    && apk del curl unzip \
    && age --version \
    && rclone --version | head -1

# Run as non-root by default
RUN adduser -D -u 1000 boxmunge
USER boxmunge

ENTRYPOINT ["sleep", "infinity"]
