"""Canary project — minimal app for boxmunge self-test."""

import http.server
import json
import os

import psycopg2


def get_conn():
    return psycopg2.connect(os.environ["DATABASE_URL"])


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS canary_data (id SERIAL PRIMARY KEY, value TEXT)")
    conn.commit()
    conn.close()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path == "/data":
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("SELECT count(*) FROM canary_data")
            count = cur.fetchone()[0]
            conn.close()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"count": count}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/data":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode() if length else "canary"
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("INSERT INTO canary_data (value) VALUES (%s)", (body,))
            conn.commit()
            conn.close()
            self.send_response(201)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    init_db()
    server = http.server.HTTPServer(("0.0.0.0", 8080), Handler)
    server.serve_forever()
