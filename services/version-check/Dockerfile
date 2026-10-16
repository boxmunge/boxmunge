FROM python:3.14-alpine@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY app.py db_schema.py failure_store.py release_catalog.py request_limits.py ./
COPY releases.json .
COPY static/ static/

EXPOSE 8147

# Migrate the database (and run the first sweep) once, before any worker
# starts: workers only check the schema version. Not --preload: per-worker
# state (check counter, sweeper thread) must be created after the fork.
CMD ["sh", "-c", "python db_schema.py /data/checks.db && exec gunicorn --bind 0.0.0.0:8147 --workers 2 --access-logfile - 'app:create_app()'"]
