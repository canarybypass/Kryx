"""
Hexor Tool Integrations — wrappers around real pentesting tools
"""
import os
import json
import asyncio
import shutil
from pathlib import Path

SANDBOX_DIR = Path(os.getenv("HEXOR_SANDBOX_DIR", "/tmp/hexor-sandbox"))

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


async def _http_probe(url: str) -> dict:
    import httpx

    if not url.startswith("http"):
        urls = [f"https://{url}", f"http://{url}"]
    else:
        urls = [url]

    last_err = None
    for u in urls:
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
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
    # interrupted) run. Drop slow time-based(T) technique to fit the budget.
    result = await _run([
        "sqlmap", "-u", url,
        "--batch", "--random-agent", "--flush-session",
        "--level", "2", "--risk", "2",
        "--technique", "BEUS",
    ], timeout=150)

    out = result.get("stdout", "")
    low = out.lower()
    vulnerable = ("is vulnerable" in low) or ("parameter" in low and "injectable" in low)

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