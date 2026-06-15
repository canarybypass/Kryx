"""
Kryx Authorization Gate — the legal safety rail.

The engine refuses to actively scan any host that is not explicitly authorized.
A host is authorized only if it is:
  - a local/lab host (loopback / private IP / localhost), OR
  - listed in authorized_scopes.txt (your own assets / explicitly permitted), OR
  - in a fetched bug-bounty in-scope list (discovery.py).

Everything else is DENIED. This is what keeps autonomous discovery legal:
we can find targets, but only ever touch authorized ones.
"""
import os
import ipaddress
from pathlib import Path
from urllib.parse import urlparse

ALLOWLIST_FILE = Path(os.getenv("KRYX_ALLOWLIST", str(Path(__file__).parent / "authorized_scopes.txt")))


def _host_of(target: str) -> str:
    if "://" not in target:
        target = "http://" + target
    return (urlparse(target).hostname or "").lower()


def _is_local(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return host in ("localhost", "localhost.localdomain")


def _load_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [l.strip().lower() for l in path.read_text().splitlines()
            if l.strip() and not l.lstrip().startswith("#")]


def _match(host: str, patterns: list[str]) -> str | None:
    for p in patterns:
        if p.startswith("*."):
            base = p[2:]
            if host == base or host.endswith("." + base):
                return p
        elif host == p:
            return p
    return None


def is_authorized(target: str) -> tuple[bool, str]:
    """Return (allowed, reason). Default DENY."""
    host = _host_of(target)
    if not host:
        return False, "could not parse a host from target"

    if _is_local(host):
        return True, f"local/lab host ({host})"

    m = _match(host, _load_lines(ALLOWLIST_FILE))
    if m:
        return True, f"authorized scope ({m})"

    # Bug-bounty in-scope (lazy import to avoid hard dependency)
    try:
        from core.autonomous.discovery import load_cached_scopes
        bm = _match(host, load_cached_scopes())
        if bm:
            return True, f"bug-bounty in-scope ({bm})"
    except Exception:
        pass

    return False, (f"'{host}' is NOT in any authorized scope — refusing to scan. "
                   f"Add it to {ALLOWLIST_FILE.name} (your assets / explicit permission) "
                   f"or ensure it's in a fetched bounty scope.")
