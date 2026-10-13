# A static site served by unprivileged nginx on port 8080. It runs as a
# non-root user and writes only under /tmp, so it works with boxmunge's
# read-only root filesystem. Replace it with your app.
FROM nginxinc/nginx-unprivileged:stable-alpine
COPY site/ /usr/share/nginx/html/
