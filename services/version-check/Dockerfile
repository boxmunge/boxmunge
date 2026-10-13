FROM python:3.12-alpine@sha256:236173eb74001afe2f60862de935b74fcbd00adfca247b2c27051a70a6a39a2d

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py release_catalog.py ./
COPY releases.json .
COPY static/ static/

EXPOSE 8147

CMD ["gunicorn", "--bind", "0.0.0.0:8147", "--workers", "2", "--access-logfile", "-", "app:create_app()"]
