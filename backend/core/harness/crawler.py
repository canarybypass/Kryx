"""
Kryx Crawl Stage — JS-aware attack-surface discovery.

Modern apps (React/Angular/Vue) build their real endpoints with JavaScript, so
a plain HTTP crawler sees only the skeleton. This crawler renders each page in a
headless browser and captures:
  - links from the RENDERED DOM (after JS runs)
  - network requests the app fires (XHR/fetch) — where the real API endpoints
    and parameters live
  - forms (and turns GET forms into testable param endpoints)
Static assets (images/css/js/fonts/media) are skipped so the budget goes to
real endpoints. Falls back to a plain HTTP crawl if the browser is unavailable.
"""
import os
import re
import asyncio
from urllib.parse import urlparse, urljoin, parse_qs

import httpx

ASSET_RE = re.compile(r"\.(png|jpe?g|gif|svg|ico|webp|css|js|mjs|woff2?|ttf|eot|map|mp4|webm|pdf|zip|gz)(\?|$)", re.I)


def _is_asset(url: str) -> bool:
    return bool(ASSET_RE.search(urlparse(url).path))


class CrawlStage:
    """Render-and-capture crawler that maps the real (JS-built) attack surface."""

    def __init__(self, target: str, max_pages: int | None = None, max_depth: int = 3):
        if not target.startswith("http"):
            target = f"http://{target}"
        self.target = target
        self.host = urlparse(target).netloc
        self.max_pages = max_pages or int(os.getenv("KRYX_CRAWL_PAGES", "40"))
        self.max_depth = max_depth

    async def run(self) -> dict:
        try:
            return await self._browser_crawl()
        except Exception as e:
            # Browser unavailable — degrade gracefully to a plain HTTP crawl.
            res = await self._http_crawl()
            res["note"] = f"JS crawl unavailable ({type(e).__name__}); used HTTP fallback."
            return res

    # ── JS-aware crawl ─────────────────────────────────────────
    async def _browser_crawl(self) -> dict:
        from playwright.async_api import async_playwright

        visited: set[str] = set()
        endpoints: dict = {}
        queue: list[tuple[str, int]] = [(self.target, 0)]

        from core.harness.auth_context import auth_headers, auth_cookies
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
            ctx = await browser.new_context(ignore_https_errors=True,
                                            extra_http_headers=auth_headers() or None)
            _ck = [{"name": k, "value": v, "url": self.target}
                   for k, v in auth_cookies().items()]
            if _ck:
                await ctx.add_cookies(_ck)
            try:
                while queue and len(visited) < self.max_pages:
                    url, depth = queue.pop(0)
                    norm = url.split("#")[0]
                    if norm in visited or depth > self.max_depth or _is_asset(norm):
                        continue
                    visited.add(norm)

                    page = await ctx.new_page()
                    captured: list[str] = []
                    page.on("request", lambda req: captured.append(req.url))
                    try:
                        await page.goto(norm, wait_until="networkidle", timeout=15000)
                    except Exception:
                        try:
                            await page.goto(norm, wait_until="load", timeout=10000)
                        except Exception:
                            await page.close()
                            continue

                    # Links + forms from the RENDERED DOM
                    try:
                        links = await page.eval_on_selector_all(
                            "a[href]", "els => els.map(e => e.href)")
                    except Exception:
                        links = []
                    try:
                        forms = await page.eval_on_selector_all("form", """els => els.map(f => ({
                            action: f.action, method: (f.method||'get').toLowerCase(),
                            inputs: Array.from(f.querySelectorAll('[name]')).map(i => i.name)
                        }))""")
                    except Exception:
                        forms = []
                    await page.close()

                    # Record the page itself + any GET forms as testable endpoints
                    self._record(norm, forms, endpoints)

                    # Captured XHR/fetch URLs reveal real API endpoints + params
                    for rurl in captured:
                        if urlparse(rurl).netloc == self.host and parse_qs(urlparse(rurl).query):
                            self._record(rurl.split("#")[0], [], endpoints)

                    # Queue same-host, non-asset links
                    for raw in links:
                        nxt = raw.split("#")[0]
                        if urlparse(nxt).netloc == self.host and not _is_asset(nxt) and nxt not in visited:
                            queue.append((nxt, depth + 1))
            finally:
                await browser.close()

        eps = list(endpoints.values())
        return {"base": self.target, "host": self.host, "pages_crawled": len(visited),
                "endpoint_count": len(eps), "endpoints": eps, "engine": "browser"}

    def _record(self, url: str, forms: list, endpoints: dict):
        parsed = urlparse(url)
        params = sorted(parse_qs(parsed.query).keys())

        norm_forms = []
        for f in forms or []:
            inputs = sorted({n for n in f.get("inputs", []) if n})
            if not inputs:
                continue
            action = f.get("action") or url
            method = f.get("method", "get")
            norm_forms.append({"action": action, "method": method, "inputs": inputs})
            # A GET form is a testable param endpoint: action?input=test...
            if method == "get":
                fp = urlparse(action)
                synth = f"{fp.scheme}://{fp.netloc}{fp.path}?" + "&".join(f"{n}=test" for n in inputs)
                self._add(endpoints, synth, [])

        self._add(endpoints, url, norm_forms, params)

    def _add(self, endpoints: dict, url: str, forms: list, params: list | None = None):
        parsed = urlparse(url)
        if params is None:
            params = sorted(parse_qs(parsed.query).keys())
        key = (parsed.path, frozenset(params))
        if key not in endpoints:
            endpoints[key] = {"url": url, "path": parsed.path, "params": params, "forms": forms}
        elif forms and not endpoints[key]["forms"]:
            endpoints[key]["forms"] = forms

    # ── Plain HTTP fallback ────────────────────────────────────
    async def _http_crawl(self) -> dict:
        link_re = re.compile(r'(?:href|src|action)=["\']([^"\'#> ]+)', re.I)
        visited: set[str] = set()
        endpoints: dict = {}
        queue: list[tuple[str, int]] = [(self.target, 0)]
        from core.harness.auth_context import client as _auth_client
        async with _auth_client(timeout=8, follow_redirects=True, verify=False) as client:
            while queue and len(visited) < self.max_pages:
                url, depth = queue.pop(0)
                norm = url.split("#")[0]
                if norm in visited or depth > self.max_depth or _is_asset(norm):
                    continue
                visited.add(norm)
                try:
                    body = (await client.get(norm)).text
                except Exception:
                    continue
                self._add(endpoints, norm, [])
                for raw in link_re.findall(body):
                    nxt = urljoin(norm, raw).split("#")[0]
                    if urlparse(nxt).netloc == self.host and not _is_asset(nxt) and nxt not in visited:
                        queue.append((nxt, depth + 1))
        eps = list(endpoints.values())
        return {"base": self.target, "host": self.host, "pages_crawled": len(visited),
                "endpoint_count": len(eps), "endpoints": eps, "engine": "http"}
