import asyncio
import socket
import ssl
import dns.resolver
import whois
import httpx
from datetime import datetime


async def run_recon(target: str) -> dict:
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    results = await asyncio.gather(
        _dns(domain),
        _whois(domain),
        _ssl(domain),
        _ports(domain),
        _headers(domain),
        return_exceptions=True,
    )

    keys = ["dns", "whois", "ssl", "ports", "headers"]
    return {k: (v if not isinstance(v, Exception) else {"error": str(v)}) for k, v in zip(keys, results)}


async def _dns(domain: str) -> dict:
    def resolve():
        out = {}
        for rtype in ["A", "MX", "NS", "TXT"]:
            try:
                out[rtype] = [r.to_text() for r in dns.resolver.resolve(domain, rtype)]
            except Exception:
                out[rtype] = []
        return out
    return await asyncio.to_thread(resolve)


async def _whois(domain: str) -> dict:
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


async def _ssl(domain: str) -> dict:
    def fetch():
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            return {
                "subject": dict(x[0] for x in cert["subject"]),
                "issuer": dict(x[0] for x in cert["issuer"]),
                "expires": str(expiry),
                "days_left": (expiry - datetime.utcnow()).days,
                "san": [v for _, v in cert.get("subjectAltName", [])],
            }
    return await asyncio.to_thread(fetch)


async def _ports(domain: str) -> dict:
    common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 5432, 6379, 8080, 8443]

    def scan():
        open_ports = []
        for port in common_ports:
            try:
                with socket.create_connection((domain, port), timeout=1):
                    open_ports.append(port)
            except Exception:
                pass
        return {"open": open_ports}

    return await asyncio.to_thread(scan)


async def _headers(domain: str) -> dict:
    url = f"https://{domain}"
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            r = await client.head(url)
            return dict(r.headers)
    except Exception:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            r = await client.head(f"http://{domain}")
            return dict(r.headers)
