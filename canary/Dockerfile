FROM python:3.12-slim
RUN pip install --no-cache-dir psycopg2-binary
COPY app.py /app/app.py
WORKDIR /app
CMD ["python", "app.py"]
