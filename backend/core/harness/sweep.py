"""
Kryx Sweep Stage — deterministic detector pass over the discovered surface.

For every endpoint/param found by the crawler, run the relevant deterministic
detectors (sqli, xss, dom-xss, cmdi, ssti, lfi, idor, ssrf) regardless of what
the LLM "feels like" trying. This guarantees coverage; the LLM hunters then add
reasoning (chaining, business logic) on top. Findings are tool-confirmed, so
they're marked exploitability=confirmed and survive validation.
"""
import os
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
    "open_redirect_probe": ("Open Redirect", "medium", "cors_ssrf"),
    "cors_probe": ("CORS Misconfiguration", "medium", "cors_ssrf"),
    "sensitive_files": ("Exposed sensitive file", "high", "config_exposure"),
}

URL_KW = ("url", "uri", "link", "fetch", "dest", "redirect", "next", "callback",
          "target", "feed", "img", "image", "load", "proxy", "site", "host", "domain")

# json_body_probe reports a per-field CLASS; map each to title/severity/remediation.
JSON_CLASS_META = {
    "cmdi": ("cmdi_probe", "OS Command Injection (RCE)", "critical", "injection"),
    "ssti": ("ssti_probe", "Server-Side Template Injection (RCE)", "critical", "injection"),
    "sqli": ("sqlmap_check", "SQL Injection", "high", "injection"),
    "xss":  ("xss_probe", "Cross-Site Scripting (XSS)", "high", "xss_csrf"),
}

# Concrete, class-specific remediation for each deterministic finding.
REMEDIATION = {
    "sqlmap_check": "Use parameterized queries / prepared statements; never concatenate user input into SQL. Apply least-privilege DB accounts.",
    "cmdi_probe": "Never pass user input to a shell. Use subprocess/exec with an argument list and shell=False; validate/allowlist input.",
    "ssti_probe": "Don't render user input as a template. Use a sandboxed engine with autoescape; never eval() user data.",
    "lfi_probe": "Canonicalize the path and confine it to a fixed base dir (reject '..'); prefer an allowlist of permitted files.",
    "xss_probe": "Apply context-aware output encoding; set a strict Content-Security-Policy; sanitize stored content on output.",
    "dom_xss_probe": "Avoid innerHTML/document.write/eval with untrusted data; use textContent/safe DOM APIs or a sanitizer (DOMPurify).",
    "idor_probe": "Enforce object-level authorization: verify the requested object belongs to the authenticated user before returning it.",
    "ssrf_probe": "Allowlist outbound hosts; block internal ranges and cloud metadata (169.254.169.254, 127.0.0.0/8, 10/8, 192.168/16); disable redirects.",
    "open_redirect_probe": "Validate redirect targets against an allowlist of internal paths/hosts; never redirect to a raw user-supplied URL.",
    "cors_probe": "Allowlist specific trusted origins; never reflect an arbitrary Origin or combine wildcard/reflected origin with Allow-Credentials.",
    "sensitive_files": "Remove the file from the web root; block dotfiles/backups at the server (nginx/apache); rotate any leaked secrets immediately.",
}


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

        # Site-level: exposed files + CORS (app-wide behaviors, run once).
        base = self.surface.get("base", "")
        sf = await run_tool("sensitive_files", {"url": base})
        if _is_vuln("sensitive_files", sf):
            findings.append(self._finding("sensitive_files", base, sf, "exposed files"))
        cors = await run_tool("cors_probe", {"url": base})
        if _is_vuln("cors_probe", cors):
            cf = self._finding("cors_probe", base, cors, "CORS")
            cf["severity"] = cors.get("severity", "medium")
            findings.append(cf)

        # Site-level: nuclei template engine (thousands of known CVE/exposure/
        # misconfig checks). Runs once on the base; each match is a concrete
        # signature hit, so it slots in as a tool-confirmed finding.
        if os.getenv("KRYX_NUCLEI", "1") != "0":
            nu = await run_tool("nuclei_scan", {"target": base})
            for nf in nu.get("findings", []):
                if nf.get("severity") in ("critical", "high", "medium", "low"):
                    findings.append(self._nuclei_finding(base, nf))
                    if self.emit:
                        await self.emit("sweep_hit", {"tool": "nuclei",
                                                      "template": nf.get("template_id")})

        # Per-endpoint deterministic detector pass. Bound concurrency so a big
        # surface doesn't fork dozens of sqlmap processes at once (full coverage,
        # just throttled — like a real scanner).
        sem = asyncio.Semaphore(int(os.getenv("KRYX_SWEEP_CONCURRENCY", "6")))

        async def _bounded(e):
            async with sem:
                return await self._sweep_endpoint(e)

        results = await asyncio.gather(
            *[_bounded(e) for e in self.surface.get("endpoints", [])],
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
            # vtype keeps distinct JSON-body classes (cmdi/sqli/ssti all share the
            # coarse "injection" attack_class) from collapsing into one another.
            key = (f.get("vtype") or f.get("attack_class"), path)
            if key not in best or rank.get(f["severity"], 0) > rank.get(best[key]["severity"], 0):
                best[key] = f
        return list(best.values())

    def _detectors_for(self, endpoint: dict) -> list[str]:
        params = endpoint.get("params", [])
        tools = ["dom_xss_probe"]  # hash-based; relevant to any page
        if params:
            tools += ["sqlmap_check", "xss_probe", "cmdi_probe", "ssti_probe",
                      "lfi_probe", "open_redirect_probe"]
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
        # JSON-body API endpoints (POST/PUT with a captured JSON body) get the
        # field-by-field JSON-body probe instead of the URL-param detectors.
        if endpoint.get("body"):
            return await self._sweep_body(endpoint)

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

    def _nuclei_finding(self, base: str, nf: dict) -> dict:
        name = nf.get("name") or nf.get("template_id") or "nuclei match"
        at = nf.get("matched_at") or base
        refs = nf.get("reference") or []
        return {
            "name": f"{name} @ {at}",
            "severity": nf.get("severity", "medium"),
            "attack_class": "cve_misconfig",
            # template-id keeps distinct nuclei hits from collapsing in dedup
            "vtype": f"nuclei:{nf.get('template_id')}",
            "description": (nf.get("description")
                            or f"nuclei template '{nf.get('template_id')}' matched on {at}.").strip(),
            "evidence": json.dumps(nf, ensure_ascii=False)[:1500],
            "exploitability": "confirmed",
            "remediation": ("Patch/remediate per the template references: " + "; ".join(refs)) if refs
                           else "Review the matched template and remediate the underlying issue.",
            "source": "sweep",
            "url": at,
            "tool": "nuclei",
        }

    async def _sweep_body(self, endpoint: dict) -> list:
        url = endpoint["url"]
        method = endpoint.get("method", "POST")
        found = []
        try:
            result = await run_tool("json_body_probe",
                                    {"url": url, "body": endpoint["body"], "method": method})
        except Exception:
            return found
        if not result.get("vulnerable"):
            return found
        where = endpoint.get("path", "") or url
        for f in result.get("findings", []):
            meta = JSON_CLASS_META.get(f.get("class", ""))
            if not meta:
                continue
            tool, title, sev, ac = meta
            field = f.get("field", "?")
            found.append({
                "name": f"{title} @ {method} {where} (JSON field '{field}')",
                "severity": sev,
                "attack_class": ac,
                "vtype": f.get("class"),
                "description": (f"{title} in the JSON body field '{field}' of "
                                f"{method} {url}. Proof: {f.get('proof', '')}"),
                "evidence": json.dumps({"method": method, "url": url, "field": field,
                                        "payload": f.get("payload"), "proof": f.get("proof")},
                                       ensure_ascii=False)[:1500],
                "exploitability": "confirmed",
                "remediation": REMEDIATION.get(tool, ""),
                "source": "sweep",
                "url": url,
            })
            if self.emit:
                await self.emit("sweep_hit", {"tool": "json_body_probe", "url": url,
                                              "class": f.get("class")})
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
            "remediation": REMEDIATION.get(tool, ""),
            "source": "sweep",
            "url": url,
        }
