"""
Kryx Sweep Stage — deterministic detector pass over the discovered surface.

For every endpoint/param found by the crawler, run the relevant deterministic
detectors (sqli, xss, dom-xss, cmdi, ssti, lfi, idor, ssrf) regardless of what
the LLM "feels like" trying. This guarantees coverage; the LLM hunters then add
reasoning (chaining, business logic) on top. Findings are tool-confirmed, so
they're marked exploitability=confirmed and survive validation.
"""
import json
import asyncio
from urllib.parse import urlparse, parse_qs

from core.tools.scanner import run_tool

# tool -> (title, severity, attack_class)
META = {
    "sqlmap_check": ("SQL Injection", "high", "injection"),
    "cmdi_probe": ("OS Command Injection (RCE)", "critical", "injection"),
    "ssti_probe": ("Server-Side Template Injection (RCE)", "critical", "injection"),
    "lfi_probe": ("Path Traversal / LFI", "high", "info_disclosure"),
    "xss_probe": ("Cross-Site Scripting (XSS)", "high", "xss_csrf"),
    "dom_xss_probe": ("DOM-based XSS", "high", "xss_csrf"),
    "idor_probe": ("IDOR / Broken Object-Level Authorization", "critical", "auth_session"),
    "ssrf_probe": ("Server-Side Request Forgery (SSRF)", "high", "cors_ssrf"),
    "sensitive_files": ("Exposed sensitive file", "high", "config_exposure"),
}

URL_KW = ("url", "uri", "link", "fetch", "dest", "redirect", "next", "callback",
          "target", "feed", "img", "image", "load", "proxy", "site", "host", "domain")


def _is_vuln(tool: str, result: dict) -> bool:
    if not isinstance(result, dict):
        return False
    if tool == "sensitive_files":
        return bool(result.get("exposed_files"))
    return bool(result.get("vulnerable"))


class SweepStage:
    """Deterministic detector sweep over every discovered endpoint."""

    def __init__(self, surface: dict, emit_cb=None):
        self.surface = surface
        self.emit = emit_cb

    async def run(self) -> list:
        findings = []

        # Site-level: probe for exposed sensitive files once.
        sf = await run_tool("sensitive_files", {"url": self.surface.get("base", "")})
        if _is_vuln("sensitive_files", sf):
            findings.append(self._finding("sensitive_files", self.surface["base"], sf, "exposed files"))

        # Per-endpoint deterministic detector pass (concurrent across endpoints).
        results = await asyncio.gather(
            *[self._sweep_endpoint(e) for e in self.surface.get("endpoints", [])],
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return self._dedupe(findings)

    @staticmethod
    def _dedupe(findings: list) -> list:
        """Collapse duplicates of the same vuln class on the same path (e.g.
        reflected + dom XSS both flagging one endpoint), keeping the highest
        severity."""
        rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        best: dict = {}
        for f in findings:
            path = urlparse(f.get("url", "")).path or f.get("url", "")
            key = (f.get("attack_class"), path)
            if key not in best or rank.get(f["severity"], 0) > rank.get(best[key]["severity"], 0):
                best[key] = f
        return list(best.values())

    def _detectors_for(self, endpoint: dict) -> list[str]:
        params = endpoint.get("params", [])
        tools = ["dom_xss_probe"]  # hash-based; relevant to any page
        if params:
            tools += ["sqlmap_check", "xss_probe", "cmdi_probe", "ssti_probe", "lfi_probe"]
            # IDOR only when a param value is numeric
            qs = parse_qs(urlparse(endpoint["url"]).query)
            if any(v and v[0].lstrip("-").isdigit() for v in qs.values()):
                tools.append("idor_probe")
            # SSRF only when a param name looks like it takes a URL/host
            if any(any(w in p.lower() for w in URL_KW) for p in params):
                tools.append("ssrf_probe")
        elif endpoint.get("forms"):
            tools.append("xss_probe")  # forms handled by xss_probe
        return tools

    async def _sweep_endpoint(self, endpoint: dict) -> list:
        url = endpoint["url"]
        found = []
        for tool in self._detectors_for(endpoint):
            try:
                result = await run_tool(tool, {"url": url})
            except Exception:
                continue
            if _is_vuln(tool, result):
                found.append(self._finding(tool, url, result, endpoint.get("path", "")))
                if self.emit:
                    await self.emit("sweep_hit", {"tool": tool, "url": url})
        return found

    def _finding(self, tool: str, url: str, result: dict, where: str) -> dict:
        title, sev, cls = META[tool]
        return {
            "name": f"{title} @ {where or url}",
            "severity": sev,
            "attack_class": cls,
            "description": f"{title} confirmed by {tool} on {url}.",
            "evidence": json.dumps(result, ensure_ascii=False)[:1500],
            "exploitability": "confirmed",
            "source": "sweep",
            "url": url,
        }
