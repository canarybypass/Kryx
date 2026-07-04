"""
Kryx local testbed - an INTENTIONALLY VULNERABLE web app for validating the
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
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Download dir for the path-traversal demo (planted vuln).
os.makedirs("downloads", exist_ok=True)
with open("downloads/readme.txt", "w") as _f:
    _f.write("public readme\n")

# In-memory store for the stored-XSS guestbook (planted vuln).
COMMENTS = []

# Private per-user accounts. /api/account?id=N returns any of these with NO
# ownership check -> IDOR / BOLA (planted vuln).
ACCOUNTS = {
    1: {"owner": "admin", "balance": 100000, "private_token": "tok_admin_SECRET"},
    2: {"owner": "alice", "balance": 4200, "private_token": "tok_alice_SECRET"},
    3: {"owner": "bob", "balance": 999, "private_token": "tok_bob_SECRET"},
}

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
            self._send(200, "<h1>Kryx Testbed</h1>"
                            "<a href='/search?q=hi'>search</a> "
                            "<a href='/user?id=1'>user</a> "
                            "<a href='/guestbook'>guestbook</a> "
                            "<a href='/page#name=hi'>page</a> "
                            "<a href='/api/account?id=1'>my account</a> "
                            "<a href='/fetch?url=http://example.com'>fetch</a> "
                            "<a href='/ping?host=127.0.0.1'>ping</a> "
                            "<a href='/download?file=readme.txt'>download</a> "
                            "<a href='/greet?name=guest'>greet</a> "
                            "<a href='/buy?item=widget&price=100&qty=1'>buy</a> "
                            "<a href='/dashboard?q=hi'>dashboard</a> "
                            "<a href='/redirect?url=/'>redirect</a> "
                            "<a href='/api/data'>api-data</a>"
                            # JS-fired JSON XHRs so the crawler discovers the
                            # POST/JSON API endpoints (real SPAs work this way).
                            "<script>"
                            "fetch('/api/search',{method:'POST',"
                            "headers:{'Content-Type':'application/json'},"
                            "body:JSON.stringify({q:'hi'})});"
                            "fetch('/api/exec',{method:'POST',"
                            "headers:{'Content-Type':'application/json'},"
                            "body:JSON.stringify({host:'127.0.0.1'})});"
                            "</script>")

        elif u.path == "/guestbook":                       # stored XSS
            items = "".join(f"<li>{c}</li>" for c in COMMENTS)  # unescaped on purpose
            self._send(200,
                       "<h2>Guestbook</h2>"
                       "<form method='POST' action='/guestbook'>"
                       "<input name='comment'><button>Post</button></form>"
                       f"<ul>{items}</ul>")

        elif u.path == "/page":                            # DOM XSS sink
            self._send(200,
                       "<h2>Welcome</h2><div id='out'></div>"
                       "<script>document.getElementById('out').innerHTML = "
                       "decodeURIComponent(location.hash.slice(1).split('name=')[1]||'');</script>")

        elif u.path == "/.env":                            # exposed secrets
            self._send(200, "DB_PASSWORD=supersecret123\nSTRIPE_SECRET_KEY=sk_live_AAAA\n",
                       ctype="text/plain")

        elif u.path == "/search":                          # reflected XSS
            term = q.get("q", [""])[0]
            self._send(200, f"<h2>Results for: {term}</h2>")  # unescaped on purpose

        elif u.path == "/download":                        # path traversal / LFI
            fname = q.get("file", ["readme.txt"])[0]
            try:
                with open("downloads/" + fname, "rb") as f:   # no sanitization
                    self._send(200, b"<pre>" + f.read()[:1000] + b"</pre>")
            except Exception as e:
                self._send(404, f"<pre>not found: {html.escape(str(e))}</pre>")

        elif u.path == "/greet":                           # SSTI
            name = q.get("name", ["guest"])[0]
            def _render(m):
                try:
                    return str(eval(m.group(1), {"__builtins__": {}}, {}))  # template eval
                except Exception:
                    return m.group(0)
            out = re.sub(r"\{\{(.+?)\}\}", _render, f"Hello {name}")
            self._send(200, f"<p>{out}</p>")

        elif u.path == "/ping":                            # command injection
            host = q.get("host", ["127.0.0.1"])[0]
            import subprocess
            out = subprocess.getoutput(f"echo PING {host}")   # shell=True -> injectable
            self._send(200, f"<pre>{out}</pre>")

        elif u.path == "/fetch":                           # SSRF
            # Server fetches an attacker-controlled URL with no allowlist.
            target = q.get("url", [""])[0]
            try:
                import urllib.request as _r
                data = _r.urlopen(target, timeout=4).read()[:500]
                self._send(200, b"<pre>" + data + b"</pre>")
            except Exception as e:
                self._send(200, f"<pre>fetch error: {e}</pre>")

        elif u.path == "/dashboard":                       # AUTHENTICATED-only zone
            if "session=secret" not in self.headers.get("Cookie", ""):
                self._send(401, "<h1>401 - login required</h1>")
                return
            term = q.get("q", [""])[0]
            # reflected XSS reachable ONLY when authenticated
            self._send(200, f"<h2>Dashboard</h2><div>Search: {term}</div>")

        elif u.path == "/redirect":                        # open redirect
            dest = q.get("url", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", dest)             # no validation
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif u.path == "/api/data":                        # CORS misconfiguration
            origin = self.headers.get("Origin", "")
            body = json.dumps({"data": "sensitive-user-data"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)   # reflects any origin
                self.send_header("Access-Control-Allow-Credentials", "true")  # + creds = critical
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif u.path == "/buy":                             # business-logic flaw
            # Trusts client-sent price and quantity, no validation (qty<0, price tamper).
            try:
                price = float(q.get("price", ["100"])[0])
                qty = int(q.get("qty", ["1"])[0])
            except ValueError:
                self._send(400, "bad params"); return
            total = price * qty
            self._send(200, json.dumps({"item": q.get("item", ["widget"])[0],
                                        "price": price, "qty": qty,
                                        "total": total, "status": "ORDER PLACED"}),
                       ctype="application/json")

        elif u.path == "/api/account":                     # IDOR / BOLA
            # "Logged in" as user 1 via cookie, but NO ownership check:
            # any id returns any account's private data.
            try:
                acc_id = int(q.get("id", ["1"])[0])
            except ValueError:
                acc_id = 1
            acc = ACCOUNTS.get(acc_id)
            if acc:
                self._send(200, json.dumps({"id": acc_id, **acc}), ctype="application/json")
            else:
                self._send(404, json.dumps({"error": "not found"}), ctype="application/json")

        elif u.path == "/user":                            # SQL injection
            uid = q.get("id", ["1"])[0]
            try:
                # raw string interpolation - classic SQLi
                cur = DB.execute(f"SELECT id,name,email FROM users WHERE id = {uid}")
                rows = cur.fetchall()
                out = "".join(f"<li>{html.escape(str(r))}</li>" for r in rows)
                self._send(200, f"<ul>{out}</ul>")
            except Exception as e:
                # verbose SQL error -> enables error-based detection
                self._send(500, f"<pre>SQL error: {e}</pre>")

        else:
            self._send(404, "<h1>404</h1>")

    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        form = parse_qs(body)

        if u.path == "/guestbook":
            COMMENTS.append(form.get("comment", [""])[0])   # stored unsanitized
            self._send(200, "<p>Saved. <a href='/guestbook'>back</a></p>")

        elif u.path == "/api/search":                      # SQLi in a JSON body field
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            term = str(data.get("q", "")) if isinstance(data, dict) else ""
            try:
                cur = DB.execute(f"SELECT id,name FROM users WHERE name LIKE '%{term}%'")
                rows = cur.fetchall()
                self._send(200, json.dumps({"results": rows}), ctype="application/json")
            except Exception as e:
                # leaks a DB error -> error-based SQLi signature
                self._send(200, json.dumps({"error": f"sqlite3.OperationalError: {e}"}),
                           ctype="application/json")

        elif u.path == "/api/exec":                        # cmdi in a JSON body field
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            host = str(data.get("host", "127.0.0.1")) if isinstance(data, dict) else "127.0.0.1"
            import subprocess
            out = subprocess.getoutput(f"echo PING {host}")   # shell=True -> injectable
            self._send(200, json.dumps({"out": out}), ctype="application/json")

        else:
            self._send(404, "<h1>404</h1>")


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", 8899), Handler)
    print("Kryx testbed listening on http://127.0.0.1:8899")
    srv.serve_forever()
