FROM python:3.12-alpine@sha256:236173eb74001afe2f60862de935b74fcbd00adfca247b2c27051a70a6a39a2d

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY app.py db_schema.py failure_store.py release_catalog.py request_limits.py stats_page.py ./
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
CMD ["sh", "-c", "python db_schema.py /data/checks.db && exec gunicorn --bind 0.0.0.0:8147 --workers 2 --access-logfile - 'app:create_app()'"]
