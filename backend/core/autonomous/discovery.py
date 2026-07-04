"""
Kryx Discovery - find AUTHORIZED targets to scan.

Pulls aggregated, daily-updated bug-bounty in-scope domains/wildcards from a
public feed (arkadiyt/bounty-targets-data). Being in-scope means the program
authorizes testing of those hosts. Cached locally; the authz gate reads the
cache so the engine only ever touches authorized hosts.

NOTE: in-scope authorizes testing, but each program may still restrict
AUTOMATED scanning - review the program's policy before mass-scanning.
"""
import asyncio
from pathlib import Path

import httpx

CACHE = Path(__file__).parent / "bounty_scopes_cache.txt"
FEEDS = [
    "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/domains.txt",
    "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/wildcards.txt",
]


async def fetch_bounty_scopes() -> int:
    """Download in-scope domains/wildcards into the local cache. Returns count."""
    scopes: set[str] = set()
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
        for url in FEEDS:
            try:
                r = await c.get(url)
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        s = line.strip().lower()
                        # keep only plain domains / *.wildcards (skip URLs, IPs, junk)
                        if s and "/" not in s and " " not in s and "." in s:
                            scopes.add(s)
            except Exception:
                pass
    if scopes:
        CACHE.write_text("\n".join(sorted(scopes)))
    return len(scopes)


def load_cached_scopes() -> list[str]:
    if CACHE.exists():
        return [l.strip().lower() for l in CACHE.read_text().splitlines() if l.strip()]
    return []


def sample_targets(n: int = 20) -> list[str]:
    """A sample of concrete (non-wildcard) in-scope domains, ready to queue.
    Filters junk: wildcards, bare TLDs, IPs, placeholders."""
    import re
    out = []
    for s in load_cached_scopes():
        if "*" in s or s.count(".") < 1:
            continue
        if re.fullmatch(r"[\d.]+", s):           # bare IP
            continue
        if s.count(".") == 1 and len(s.split(".")[0]) <= 2:  # ".com"/".uk"-ish junk
            continue
        if any(ch in s for ch in "-_") and s.count("-") >= 4:  # placeholder-y
            continue
        out.append(s)
        if len(out) >= n:
            break
    return out


async def discover_oss_repos(query: str = "language:python stars:50..2000 pushed:>2025-01-01",
                             n: int = 10) -> list[dict]:
    """Find open-source repos to audit (white-box). Default query targets
    actively-maintained, moderately-popular projects - big enough to matter,
    small enough to be under-audited (better CVE candidates than huge repos).
    Reading public source is legal; findings go through responsible disclosure.
    """
    url = "https://api.github.com/search/repositories"
    params = {"q": query, "sort": "updated", "order": "desc", "per_page": str(n)}
    headers = {"Accept": "application/vnd.github+json"}
    async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=headers) as c:
        r = await c.get(url, params=params)
        if r.status_code != 200:
            return []
        items = r.json().get("items", [])
    return [{
        "full_name": it["full_name"],
        "url": it["html_url"],
        "stars": it.get("stargazers_count", 0),
        "language": it.get("language"),
        "size_kb": it.get("size", 0),
    } for it in items]


if __name__ == "__main__":
    count = asyncio.run(fetch_bounty_scopes())
    print(f"cached {count} authorized scope entries -> {CACHE}")
