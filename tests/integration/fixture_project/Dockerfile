FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203
RUN pip install --no-cache-dir psycopg2-binary
COPY app.py /app/app.py
WORKDIR /app
CMD ["python", "app.py"]
