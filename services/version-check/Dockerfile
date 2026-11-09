FROM python:3.15-alpine@sha256:a0f2e268f2ce8f3709611a90054ec6a8ae31f6251f5896b8648b9bb99835e30a

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY admin_auth.py admin_pages.py app.py db.py db_schema.py failure_store.py passkey_routes.py \
     prefix_store.py release_catalog.py request_limits.py retention.py stats_page.py \
     webauthn_store.py ./
COPY releases.json .
COPY static/ static/

# Run as a fixed numeric user: boxmunge 0.11 compares it with the owner of
# the check-data volume, which a name cannot be.
RUN adduser -D -u 10001 app && mkdir -p /data && chown app /data
USER 10001:10001
EXPOSE 8147

# Migrate the database (and run the first sweep) once, before any worker
# starts: workers only check the schema version. Not --preload: per-worker
# state (check counter, sweeper thread) must be created after the fork.
# gunicorn's access log (stdout, so the container log) records each
# request's full client address, like the Caddy proxy's access log; the
# privacy statement in static/index.html says so.
CMD ["sh", "-c", "python db_schema.py /data/checks.db && exec gunicorn --bind 0.0.0.0:8147 --workers 2 --access-logfile - 'app:create_app()'"]
