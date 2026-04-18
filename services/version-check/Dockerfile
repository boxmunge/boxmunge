FROM python:3.12-alpine

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY releases.json .
COPY static/ static/

EXPOSE 8147

CMD ["gunicorn", "--bind", "0.0.0.0:8147", "--workers", "2", "--access-logfile", "-", "app:create_app()"]
