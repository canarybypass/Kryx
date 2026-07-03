"""
Kryx Supervisor — главный оркестратор многоагентной системы
"""
import re
from urllib.parse import urlparse
from dataclasses import dataclass, field


_SEV_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _finding_path(f: dict) -> str:
    """Best-effort endpoint path. From url if present, else the longest path-like
    token in the name (avoids grabbing 'IDOR/BOLA'); '' for site-level findings
    so same-type site-level findings collapse together."""
    u = f.get("url", "")
    if u:
        p = urlparse(u).path
        return p if p not in ("", "/") else ""  # root == site-level
    cands = re.findall(r"/[\w.\-/%?=&]+", f.get("name", "") or "")
    if cands:
        return max(cands, key=len).split("?")[0].rstrip("/") or "/"
    return ""  # site-level


_VULN_TYPES = [
    ("rce", ("command inj", "os command", " rce", "cmdi", "remote code")),
    ("ssti", ("ssti", "template inj")),
    ("sqli", ("sql inj", "sqli")),
    ("idor", ("idor", "bola", "object-level", "object level")),
    ("ssrf", ("ssrf", "server-side request", "server side request")),
    ("lfi", ("lfi", "path traversal", "local file")),
    ("xss", ("xss", "cross-site script", "cross site script")),
    ("secret", (".env", "env file", "exposed sensitive", "sensitive information",
                "information disclosure", "secret", "credential")),
    ("logic", ("business logic", "tampering", "negative")),
    ("headers", ("security header", "missing header", "заголовк", "security-header")),
    ("outdated", ("outdated", "устаревш", "cve-", "apache 2", "php 5")),
]


def _vuln_type(f: dict) -> str:
    # Detect from the finding's own type/name — NOT attack_class (a coarse
    # hunter label like "cors_ssrf" wrongly matched headers findings as ssrf).
    # Keyword match runs FIRST so several nuclei templates that flag the same
    # known class (e.g. 3 .env templates + our sensitive_files hit) collapse
    # into one cross-source finding instead of spamming the report.
    blob = f"{f.get('type', '')} {f.get('name', '')}".lower()
    for canon, kws in _VULN_TYPES:
        if any(k in blob for k in kws):
            return canon
    # No known class matched — for a nuclei hit keep its unique template id so
    # distinct, novel CVEs on one host don't collapse into each other.
    vt = f.get("vtype", "")
    if vt.startswith("nuclei:"):
        return vt
    return f.get("attack_class") or "other"


def _clean_name(s: str) -> str:
    # Strip stray CJK / control chars some models inject into RU/EN text.
    return re.sub(r"[　-鿿가-힯\x00-\x08\x0e-\x1f]", "", s or "").strip()


# Host-wide concerns: the same issue at different paths is ONE finding. Stops
# e.g. sensitive_files (site-level) and a nuclei .env template (path /.env) from
# both surviving as separate "secret" findings.
_SITE_LEVEL_TYPES = {"secret", "headers", "cors", "outdated"}


def _dedupe_findings(findings: list) -> list:
    """Collapse the same vuln TYPE on the same endpoint across sources,
    preferring tool-confirmed (sweep/logic), then higher severity."""
    best: dict = {}
    for f in findings:
        f["name"] = _clean_name(f.get("name", ""))
        vt = _vuln_type(f)
        key = (vt, "" if vt in _SITE_LEVEL_TYPES else _finding_path(f))
        cur = best.get(key)
        if cur is None:
            best[key] = f
            continue
        pref = (f.get("source") in ("sweep", "logic"), _SEV_RANK.get(f.get("severity"), 0))
        cur_pref = (cur.get("source") in ("sweep", "logic"), _SEV_RANK.get(cur.get("severity"), 0))
        if pref > cur_pref:
            best[key] = f
    return list(best.values())
from core.harness.recon import ReconStage
from core.harness.crawler import CrawlStage
from core.harness.sweep import SweepStage
from core.harness.logic_hunter import LogicHunter
from core.harness.hunter import HunterStage
from core.harness.scan_memory import recall, remember, memory_context
from core.harness.auth_context import set_auth, clear_auth, is_authed
from core.harness.debate import DebateStage
from core.harness.chain_builder import ChainBuilderStage
from core.harness.reporter import ReporterStage


@dataclass
class ScanResult:
    target: str
    summary: str = ""
    recon: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    validated_findings: list = field(default_factory=list)
    attack_chains: list = field(default_factory=list)
    report: str = ""
    stats: dict = field(default_factory=dict)


class Supervisor:
    """Главный оркестратор. Координирует все стадии сканирования."""

    def __init__(self, target: str, max_hunters: int = 8, progress_cb=None, auth: dict | None = None):
        self.target = target
        self.max_hunters = max_hunters
        self.progress_cb = progress_cb  # async callback for WebSocket updates
        self.auth = auth or {}  # {"headers": {...}, "cookies": {...}} for authed scans
        self.result = ScanResult(target=target)

    async def run(self) -> dict:
        # Authorization gate — never actively scan a non-authorized host.
        from core.autonomous.authz import is_authorized
        ok, reason = is_authorized(self.target)
        if not ok:
            await self._emit("status", "refused")
            self.result.summary = f"REFUSED: {reason}"
            self.result.stats = {"refused": True, "reason": reason}
            return {"target": self.target, "error": "unauthorized", "reason": reason,
                    "vulnerabilities": [], "attack_chains": [], "report": "", "recon": {},
                    "stats": self.result.stats}

        # Authenticated scanning: every target request now carries the session.
        set_auth(self.auth.get("headers"), self.auth.get("cookies"))
        if is_authed():
            await self._emit("auth", {"authenticated": True})

        await self._emit("status", "recon")

        # Stage 1: Reconnaissance
        recon = ReconStage(self.target)
        self.result.recon = await recon.run()
        await self._emit("status", "crawling")
        await self._emit("recon", self.result.recon)

        # Stage 2: Crawl — map the full attack surface (endpoints, params, forms)
        surface = await CrawlStage(self.target).run()

        # Memory: merge surface from past scans (never lose endpoints) and inject
        # prior findings into recon so hunters get smarter on repeat targets.
        mem = recall(self.target)
        if mem:
            known = {(e["path"], tuple(sorted(e.get("params", []))))
                     for e in surface["endpoints"]}
            for e in mem.get("endpoints", []):
                key = (e.get("path"), tuple(sorted(e.get("params", []))))
                if key not in known:
                    surface["endpoints"].append({"url": e["url"], "path": e["path"],
                                                 "params": e.get("params", []), "forms": []})
            self.result.recon["memory"] = memory_context(mem)
            await self._emit("memory", {"scan_count": mem.get("scan_count"),
                                        "known_endpoints": len(mem.get("endpoints", []))})

        self.result.recon["crawled_endpoints"] = [e["url"] for e in surface.get("endpoints", [])]
        await self._emit("crawl", {"endpoints": len(surface.get("endpoints", []))})

        # Stage 3: Deterministic sweep — run every relevant detector on every
        # discovered endpoint. Guarantees coverage independent of the LLM.
        await self._emit("status", "sweeping")
        sweep_findings = await SweepStage(surface, self._emit).run()
        await self._emit("sweep", {"findings": len(sweep_findings)})

        # Stage 3b: Business-logic hunting — flaws scanners can't find
        # (negative price, price/role tampering), confirmed by server response.
        await self._emit("status", "business_logic")
        logic_findings = await LogicHunter(surface, self._emit).run()
        await self._emit("logic", {"findings": len(logic_findings)})

        # Stage 4: Parallel LLM hunting (reasoning on top of the sweep)
        await self._emit("status", "hunting")
        hunter = HunterStage(self.target, self.result.recon, self.max_hunters,
                             self._emit, surface=surface)
        hunter_findings = await hunter.run()

        # Merge deterministic + business-logic + LLM findings, then collapse
        # cross-source duplicates (same vuln class on same endpoint).
        self.result.findings = _dedupe_findings(sweep_findings + logic_findings + hunter_findings)
        await self._emit("findings_raw", self.result.findings)

        # Stage 5: Adversarial debate (visible attacker vs defender) — verifies
        # LLM findings via a live multi-turn debate; tool-confirmed pass through.
        await self._emit("status", "debate")
        debate = DebateStage(self.target, self.result.findings, self._emit)
        self.result.validated_findings = await debate.run()
        await self._emit("status", "chains")
        await self._emit("findings_validated", self.result.validated_findings)

        # Stage 4: Chain building
        chain_builder = ChainBuilderStage(self.target, self.result.validated_findings)
        self.result.attack_chains = await chain_builder.run()
        await self._emit("chains", self.result.attack_chains)

        # Stage 5: Report generation
        reporter = ReporterStage(self.target, self.result)
        self.result.report, self.result.summary = await reporter.run()
        await self._emit("status", "done")
        await self._emit("report", {"report": self.result.report, "summary": self.result.summary})

        # Stats
        self.result.stats = {
            "total_findings": len(self.result.findings),
            "validated": len(self.result.validated_findings),
            "chains": len(self.result.attack_chains),
            "by_severity": self._count_by_severity(self.result.validated_findings),
        }

        # Remember this scan (accumulate surface + findings for next time).
        try:
            remember(
                self.target,
                [{"url": e["url"], "path": e["path"], "params": e.get("params", [])}
                 for e in surface.get("endpoints", [])],
                self.result.validated_findings,
            )
        except Exception:
            pass

        clear_auth()  # don't leak this scan's session into the next
        return self._to_dict()

    async def _emit(self, event: str, data):
        if self.progress_cb:
            await self.progress_cb({"event": event, "data": data})

    def _count_by_severity(self, findings: list) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "low")
            if sev in counts:
                counts[sev] += 1
        return counts

    def _to_dict(self) -> dict:
        return {
            "target": self.result.target,
            "summary": self.result.summary,
            "attack_chains": self.result.attack_chains,
            "vulnerabilities": self.result.validated_findings,
            "report": self.result.report,
            "recon": self.result.recon,
            "stats": self.result.stats,
        }


# Backward compatibility
async def run_agent(target: str, max_steps: int = 15) -> dict:
    supervisor = Supervisor(target, max_hunters=8)
    return await supervisor.run()


async def run_audit(source: str, github_token: str | None = None) -> dict:
    """Shortcut for source code audit mode."""
    from core.harness.code_auditor import CodeAuditor
    auditor = CodeAuditor()
    return await auditor.run(source, github_token)