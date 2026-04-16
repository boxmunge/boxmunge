# system/Dockerfile
# boxmunge-system: lightweight container for age + rclone tooling
# Provides blast-radius containment and reproducible tool versions.

FROM alpine:3.21

ARG AGE_VERSION=1.2.1
ARG RCLONE_VERSION=1.68.2

RUN apk add --no-cache \
        ca-certificates \
        curl \
        unzip \
    && curl -fsSL "https://github.com/FiloSottile/age/releases/download/v${AGE_VERSION}/age-v${AGE_VERSION}-linux-amd64.tar.gz" \
        | tar xz -C /usr/local/bin --strip-components=1 age/age age/age-keygen \
    && curl -fsSL "https://downloads.rclone.org/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-linux-amd64.zip" -o /tmp/rclone.zip \
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
