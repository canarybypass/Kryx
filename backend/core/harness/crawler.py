"""
Kryx Crawl Stage — attack-surface discovery.

Systematically maps the target: follows same-host links, collects every
endpoint, its query parameters and forms. This is the foundation of full
coverage — the deterministic sweep then tests each discovered point, so the
engine no longer relies on the LLM to "guess" where to look.
"""
import re
import asyncio
from urllib.parse import urlparse, urljoin, parse_qs

import httpx

LINK_RE = re.compile(r'(?:href|src|action)=["\']([^"\'#> ]+)', re.I)
FORM_RE = re.compile(r"<form[^>]*>.*?</form>", re.I | re.S)
ACTION_RE = re.compile(r'action=["\']([^"\']*)', re.I)
METHOD_RE = re.compile(r'method=["\']([^"\']*)', re.I)
INPUT_RE = re.compile(r'<(?:input|textarea|select)[^>]+name=["\']([^"\']+)', re.I)


class CrawlStage:
    """Stage: discover the full attack surface (endpoints, params, forms)."""

    def __init__(self, target: str, max_pages: int = 60, max_depth: int = 3):
        if not target.startswith("http"):
            target = f"http://{target}"
        self.target = target
        self.host = urlparse(target).netloc
        self.max_pages = max_pages
        self.max_depth = max_depth

    async def run(self) -> dict:
        visited: set[str] = set()
        # endpoints keyed by (path, frozenset(params)) so we don't duplicate
        endpoints: dict = {}
        queue: list[tuple[str, int]] = [(self.target, 0)]

        async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
            while queue and len(visited) < self.max_pages:
                url, depth = queue.pop(0)
                norm = url.split("#")[0]
                if norm in visited or depth > self.max_depth:
                    continue
                visited.add(norm)

                try:
                    r = await client.get(norm)
                    body = r.text
                    ctype = r.headers.get("content-type", "")
                except Exception:
                    continue

                self._record(norm, body, endpoints)

                if "html" not in ctype.lower():
                    continue

                for raw in LINK_RE.findall(body):
                    nxt = urljoin(norm, raw).split("#")[0]
                    if urlparse(nxt).netloc != self.host:
                        continue  # same host only
                    if nxt not in visited:
                        queue.append((nxt, depth + 1))

        eps = list(endpoints.values())
        return {
            "base": self.target,
            "host": self.host,
            "pages_crawled": len(visited),
            "endpoint_count": len(eps),
            "endpoints": eps,
        }

    def _record(self, url: str, body: str, endpoints: dict):
        parsed = urlparse(url)
        params = sorted(parse_qs(parsed.query).keys())

        forms = []
        for fm in FORM_RE.findall(body):
            am = ACTION_RE.search(fm)
            mm = METHOD_RE.search(fm)
            inputs = sorted(set(INPUT_RE.findall(fm)))
            if inputs:
                forms.append({
                    "action": urljoin(url, am.group(1)) if am else url,
                    "method": (mm.group(1).lower() if mm else "get"),
                    "inputs": inputs,
                })

        key = (parsed.path, frozenset(params))
        if key not in endpoints:
            endpoints[key] = {
                "url": url,
                "path": parsed.path,
                "params": params,
                "forms": forms,
            }
        elif forms and not endpoints[key]["forms"]:
            endpoints[key]["forms"] = forms
