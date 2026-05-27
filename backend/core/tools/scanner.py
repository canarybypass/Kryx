"""
Hexor Tool Integrations — wrappers around real pentesting tools
"""
import os
import json
import asyncio
import subprocess
import shutil
from pathlib import Path

SANDBOX_DIR = Path(os.getenv("HEXOR_SANDBOX_DIR", "/tmp/hexor-sandbox"))

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
                }
        except Exception as e:
            continue

    return {"error": f"Could not connect to {url}"}


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

    result = await _run([
        "sqlmap", "-u", url,
        "--batch", "--random-agent",
        "--level", "2", "--risk", "2",
        "--technique", "BEUSTQ",
    ], timeout=120)

    vulnerable = "vulnerable" in result["stdout"].lower() and "identified the following" in result["stdout"].lower()

    return {
        "url": url,
        "vulnerable": vulnerable,
        "raw": result["stdout"][:3000],
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