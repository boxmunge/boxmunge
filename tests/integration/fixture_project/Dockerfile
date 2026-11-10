FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
RUN pip install --no-cache-dir psycopg2-binary
COPY app.py /app/app.py
WORKDIR /app
CMD ["python", "app.py"]
