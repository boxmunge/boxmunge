FROM python:3.15-alpine@sha256:2699b90f4d562a22e2dd076c82f964032f64814204bff36d271a54ba4cc2c7e2
WORKDIR /app
COPY index.html .
EXPOSE 8080
CMD ["python", "-m", "http.server", "8080"]
