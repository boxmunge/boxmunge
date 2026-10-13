# Image guidance (see 'agent-help images' on the server): slim official base,
# pinned by digest, multi-stage, non-root, read-only-rootfs friendly.
#
# PIN THE BASE BEFORE DEPLOYING. Resolve the digest and use it in both FROMs:
#   docker pull python:3.13-slim
#   docker inspect --format '{{index .RepoDigests 0}}' python:3.13-slim
#   FROM python:3.13-slim@sha256:<digest>
# Refresh it the same way when you want base-image security updates.

# Build stage: dependencies only. pip, compilers and headers stay here.
FROM python:3.13-slim AS build
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes --target /deps -r /tmp/requirements.txt

# Runtime stage: the app and its installed dependencies, nothing else.
FROM python:3.13-slim
RUN python -m pip uninstall --yes pip
COPY --from=build /deps /app/deps
COPY app.py /app/app.py
ENV PYTHONPATH=/app/deps PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Non-root. The root filesystem is read-only at runtime (only /tmp is
# writable); declare other writable paths under 'writable:' in manifest.yml.
USER 10001:10001
WORKDIR /app
EXPOSE 8080
CMD ["python", "app.py"]
