"""
Domain ownership verification - the legal gate for self-serve scans.

A user may only scan a domain they prove they control. Before any self-serve
scan runs, the requesting org must verify the target via ONE of:
  - a DNS TXT record on the domain holding their unique token, or
  - a file at https://<domain>/.well-known/kryx-verify.txt holding the token.

The token is deterministic per (org, domain) and unforgeable without the
server secret - but verification still requires the record to actually exist
on the domain, so a user can't claim a domain they don't control.
"""
import hashlib
import hmac
import os
from urllib.parse import urlparse

import httpx

_SECRET = (os.getenv("SECRET_KEY") or "kryx-dev-secret-change-me").encode()
_WELL_KNOWN = "/.well-known/kryx-verify.txt"


def normalize_domain(domain: str) -> str:
    """Bare, lowercased registrable host: strips scheme, path, port, wildcard."""
    d = (domain or "").strip().lower()
    if "://" in d:
        d = urlparse(d).hostname or d
    d = d.split("/")[0].split(":")[0]
    return d.lstrip("*.")


def verification_token(org_id: int, domain: str) -> str:
    """Stable, unguessable token for (org, domain). Same inputs -> same token,
    so re-checking is idempotent."""
    msg = f"{org_id}:{normalize_domain(domain)}".encode()
    digest = hmac.new(_SECRET, msg, hashlib.sha256).hexdigest()[:24]
    return f"kryx-verify-{digest}"


def instructions(org_id: int, domain: str) -> dict:
    """What the user must publish to prove ownership (shown in the dashboard)."""
    domain = normalize_domain(domain)
    token = verification_token(org_id, domain)
    return {
        "domain": domain,
        "token": token,
        "dns": {"type": "TXT", "host": domain, "value": token},
        "file": {"url": f"https://{domain}{_WELL_KNOWN}", "content": token},
    }


async def _dns_txt(domain: str) -> list[str]:
    """TXT records via DNS-over-HTTPS (no extra dep, works in any environment)."""
    out: list[str] = []
    for resolver in ("https://dns.google/resolve",
                     "https://cloudflare-dns.com/dns-query"):
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(resolver, params={"name": domain, "type": "TXT"},
                                headers={"accept": "application/dns-json"})
                data = r.json()
                out = [a.get("data", "").strip().strip('"')
                       for a in data.get("Answer", []) if a.get("type") == 16]
                if out:
                    return out
        except Exception:
            continue
    return out


async def _http_file(domain: str) -> str:
    for scheme in ("https", "http"):
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True,
                                         verify=False) as c:
                r = await c.get(f"{scheme}://{domain}{_WELL_KNOWN}")
                if r.status_code == 200:
                    return r.text.strip()
        except Exception:
            continue
    return ""


async def verify_domain(org_id: int, domain: str) -> tuple[bool, str]:
    """Return (verified, reason). Checks DNS TXT first, then the .well-known file."""
    domain = normalize_domain(domain)
    if not domain or "." not in domain:
        return False, "invalid domain"
    token = verification_token(org_id, domain)

    txts = await _dns_txt(domain)
    if any(token in t for t in txts):
        return True, "verified via DNS TXT record"

    if token in await _http_file(domain):
        return True, f"verified via {_WELL_KNOWN}"

    return False, ("ownership not verified - publish the token via a DNS TXT "
                   f"record on {domain} or at https://{domain}{_WELL_KNOWN}")
