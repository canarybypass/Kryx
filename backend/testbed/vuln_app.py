"""
Kryx local testbed — an INTENTIONALLY VULNERABLE web app for validating the
engine end-to-end. Localhost only. Do NOT expose this to a network.

Vulnerabilities planted (on purpose):
  - SQL injection (error-based, sqlite) at /user?id=
  - Reflected XSS at /search?q=
  - Missing security headers everywhere
  - Exposed secrets file at /.env
  - Verbose Server / X-Powered-By banners
"""
import sqlite3
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.execute("CREATE TABLE users (id INTEGER, name TEXT, email TEXT, secret TEXT)")
DB.executemany(
    "INSERT INTO users VALUES (?,?,?,?)",
    [(1, "admin", "admin@kryx.local", "FLAG{sqli_dumped_admin}"),
     (2, "alice", "alice@kryx.local", "s3cr3t-alice")],
)
DB.commit()


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.2.14"          # outdated banner on purpose
    sys_version = "PHP/5.3.1"

    def _send(self, code, body, ctype="text/html"):
        body = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Powered-By", "PHP/5.3.1")     # info disclosure
        # NOTE: deliberately NO security headers (CSP/HSTS/X-Frame-Options...)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass  # quiet

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)

        if u.path == "/":
            self._send(200, "<h1>Kryx Testbed</h1><a href='/search?q=hi'>search</a> "
                            "<a href='/user?id=1'>user</a>")

        elif u.path == "/.env":                            # exposed secrets
            self._send(200, "DB_PASSWORD=supersecret123\nSTRIPE_SECRET_KEY=sk_live_AAAA\n",
                       ctype="text/plain")

        elif u.path == "/search":                          # reflected XSS
            term = q.get("q", [""])[0]
            self._send(200, f"<h2>Results for: {term}</h2>")  # unescaped on purpose

        elif u.path == "/user":                            # SQL injection
            uid = q.get("id", ["1"])[0]
            try:
                # raw string interpolation — classic SQLi
                cur = DB.execute(f"SELECT id,name,email FROM users WHERE id = {uid}")
                rows = cur.fetchall()
                out = "".join(f"<li>{html.escape(str(r))}</li>" for r in rows)
                self._send(200, f"<ul>{out}</ul>")
            except Exception as e:
                # verbose SQL error -> enables error-based detection
                self._send(500, f"<pre>SQL error: {e}</pre>")

        else:
            self._send(404, "<h1>404</h1>")


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", 8899), Handler)
    print("Kryx testbed listening on http://127.0.0.1:8899")
    srv.serve_forever()
