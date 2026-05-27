"""
Hexor Agent Tools — инструменты которыми управляет Orchestrator
"""
import asyncio
import socket
import ssl
import json
import httpx
import dns.resolver
import whois
from datetime import datetime


TOOLS_SCHEMA = [
    {
        "name": "dns_lookup",
        "description": "Resolve DNS records (A, MX, NS, TXT) for a domain",
        "parameters": {"domain": "string"},
    },
    {
        "name": "whois_lookup",
        "description": "Get WHOIS registration info for a domain",
        "parameters": {"domain": "string"},
    },
    {
        "name": "ssl_audit",
        "description": "Audit SSL certificate: expiry, issuer, SANs, weak ciphers",
        "parameters": {"domain": "string"},
    },
    {
        "name": "port_scan",
        "description": "Scan common ports on a host to find open services",
        "parameters": {"host": "string"},
    },
    {
        "name": "http_probe",
        "description": "Probe HTTP/HTTPS endpoint: headers, status, redirects, security headers",
        "parameters": {"url": "string"},
    },
    {
        "name": "cve_lookup",
        "description": "Search NVD for CVEs matching a software/version string",
        "parameters": {"keyword": "string"},
    },
    {
        "name": "subdomain_enum",
        "description": "Enumerate common subdomains for a domain",
        "parameters": {"domain": "string"},
    },
]


async def run_tool(name: str, params: dict) -> dict:
    handlers = {
        "dns_lookup": _dns_lookup,
        "whois_lookup": _whois_lookup,
        "ssl_audit": _ssl_audit,
        "port_scan": _port_scan,
        "http_probe": _http_probe,
        "cve_lookup": _cve_lookup,
        "subdomain_enum": _subdomain_enum,
    }
    handler = handlers.get(name)
    if not handler:
        return {"error": f"Unknown tool: {name}"}
    try:
        return await handler(**params)
    except Exception as e:
        return {"error": str(e)}


async def _dns_lookup(domain: str) -> dict:
    def resolve():
        out = {}
        for rtype in ["A", "MX", "NS", "TXT"]:
            try:
                out[rtype] = [r.to_text() for r in dns.resolver.resolve(domain, rtype)]
            except Exception:
                out[rtype] = []
        return out
    return await asyncio.to_thread(resolve)


async def _whois_lookup(domain: str) -> dict:
    def fetch():
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "country": w.country,
        }
    return await asyncio.to_thread(fetch)


async def _ssl_audit(domain: str) -> dict:
    def fetch():
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            cipher = s.cipher()
            expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.utcnow()).days
            return {
                "subject": dict(x[0] for x in cert["subject"]),
                "issuer": dict(x[0] for x in cert["issuer"]),
                "expires": str(expiry),
                "days_left": days_left,
                "expired": days_left < 0,
                "expiring_soon": 0 <= days_left <= 30,
                "cipher": cipher[0] if cipher else None,
                "san": [v for _, v in cert.get("subjectAltName", [])],
            }
    return await asyncio.to_thread(fetch)


async def _port_scan(host: str) -> dict:
    ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
        27017: "MongoDB", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        9200: "Elasticsearch", 11211: "Memcached",
    }

    def scan():
        open_ports = {}
        for port, service in ports.items():
            try:
                with socket.create_connection((host, port), timeout=1):
                    open_ports[port] = service
            except Exception:
                pass
        return {"open_ports": open_ports}

    return await asyncio.to_thread(scan)


async def _http_probe(url: str) -> dict:
    if not url.startswith("http"):
        url = f"https://{url}"
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        r = await client.get(url)
        headers = dict(r.headers)
        security_headers = {
            "x-frame-options": headers.get("x-frame-options"),
            "x-content-type-options": headers.get("x-content-type-options"),
            "strict-transport-security": headers.get("strict-transport-security"),
            "content-security-policy": headers.get("content-security-policy"),
            "x-xss-protection": headers.get("x-xss-protection"),
            "referrer-policy": headers.get("referrer-policy"),
        }
        missing = [k for k, v in security_headers.items() if not v]
        return {
            "status": r.status_code,
            "server": headers.get("server"),
            "x-powered-by": headers.get("x-powered-by"),
            "security_headers": security_headers,
            "missing_security_headers": missing,
            "cookies": [str(c) for c in r.cookies.jar],
        }


async def _cve_lookup(keyword: str) -> dict:
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
                "description": cve["descriptions"][0]["value"][:200],
                "cvss": cvss,
                "published": cve["published"][:10],
            })
        return {"cves": cves, "total": data.get("totalResults", 0)}


async def _subdomain_enum(domain: str) -> dict:
    wordlist = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
        "vpn", "remote", "portal", "app", "dashboard", "beta", "old",
        "backup", "db", "mysql", "smtp", "pop", "imap", "ns1", "ns2",
    ]

    def check(sub):
        try:
            socket.gethostbyname(f"{sub}.{domain}")
            return f"{sub}.{domain}"
        except Exception:
            return None

    found = await asyncio.gather(*[asyncio.to_thread(check, s) for s in wordlist])
    return {"subdomains": [s for s in found if s]}
