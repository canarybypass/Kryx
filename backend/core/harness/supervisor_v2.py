"""
Kryx unified scan pipeline - the SaaS entrypoint.

`run_pipeline()` is the single entrypoint the SaaS API (api/routes.py) and the
webhook integrations call. It dispatches each scan to the REAL engine for its
target type and persists the results to the database:

    web / url      -> Supervisor   (live black-box engine: recon→crawl→sweep→
                                     business-logic→hunt→debate→chains→report)
    repo / source  -> CodeAuditor  (white-box taint analysis + validation)

This replaces the earlier `SupervisorV2` static-analysis pipeline, which was a
half-finished stub (fuzzing/chain/report stages were never implemented) wired in
parallel to the real engines. All engine work now lives in one place:
supervisor.py and code_auditor.py. `SupervisorV2` is kept as a thin back-compat
shim so existing imports keep working.
"""
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PipelineResult:
    target: str
    # name kept as `static_findings` for API/back-compat; holds findings from
    # whichever engine ran (live or static).
    static_findings: list = field(default_factory=list)
    summary: str = ""
    report: str = ""
    stats: dict = field(default_factory=dict)
    finished_at: datetime | None = None


# canonical vuln-type (from supervisor._vuln_type) -> DB VulnerabilityType value
_TYPE_MAP = {
    "sqli": "injection", "rce": "injection", "ssti": "injection",
    "cmdi": "injection", "injection": "injection",
    "xss": "xss", "idor": "idor", "logic": "logic_flaw",
    "ssrf": "info_disclosure", "lfi": "info_disclosure", "secret": "info_disclosure",
    "headers": "info_disclosure", "outdated": "info_disclosure",
    "config_exposure": "info_disclosure", "info_disclosure": "info_disclosure",
    "csrf": "csrf",
}


def _sev_enum(severity: str):
    from db import VulnerabilitySeverity
    s = (severity or "info").lower()
    try:
        return VulnerabilitySeverity(s)
    except ValueError:
        return VulnerabilitySeverity.INFO


def _type_enum(finding: dict):
    from db import VulnerabilityType
    from core.harness.supervisor import _vuln_type
    canon = _vuln_type(finding)
    mapped = _TYPE_MAP.get(canon)
    if mapped is None and "auth" in canon:
        mapped = "auth_bypass"
    try:
        return VulnerabilityType(mapped) if mapped else VulnerabilityType.OTHER
    except ValueError:
        return VulnerabilityType.OTHER


async def run_pipeline(target: str, target_type: str = "repo",
                       scan_id: int | None = None, db_session=None,
                       progress_cb=None, model: str | None = None) -> PipelineResult:
    """Dispatch a scan to the real engine for its target type, persist to the
    DB (when scan_id/db_session are given), and return a PipelineResult.

    `model` pins the LLM for this scan (plan-tier gating) - async-safe, scoped
    to this task only."""
    if model:
        from utils.llm import set_model_override
        set_model_override(model)

    target_type = (target_type or "repo").lower()

    if target_type in ("web", "url", "http", "https", "live"):
        from core.harness.supervisor import Supervisor
        res = await Supervisor(target, progress_cb=progress_cb).run()
        stage = "live"
    else:  # repo | source | binary -> white-box code audit
        from core.harness.code_auditor import CodeAuditor
        res = await CodeAuditor(progress_cb=progress_cb).run(target)
        stage = "static"

    findings = res.get("vulnerabilities") or res.get("findings") or []
    result = PipelineResult(
        target=target,
        static_findings=findings,
        summary=res.get("summary", ""),
        report=res.get("report", ""),
        stats=res.get("stats", {}),
        finished_at=datetime.utcnow(),
    )

    if scan_id and db_session is not None:
        await _persist(db_session, scan_id, result, findings, stage)
    return result


async def _persist(db, scan_id: int, result: PipelineResult, findings: list, stage: str):
    """Write the scan record + one Vulnerability row per finding."""
    from db import Scan, ScanStatus, Vulnerability
    try:
        scan = await db.get(Scan, scan_id)
        if not scan:
            return
        scan.status = ScanStatus.COMPLETED
        scan.summary = result.summary
        scan.report = result.report
        scan.stats = result.stats
        scan.finished_at = result.finished_at
        scan.static_analysis_done = True

        for f in findings:
            confirmed = (f.get("exploitability") == "confirmed"
                         or f.get("source") in ("sweep", "logic"))
            db.add(Vulnerability(
                scan_id=scan.id,
                organization_id=scan.organization_id,
                vuln_type=_type_enum(f),
                severity=_sev_enum(f.get("severity")),
                name=(f.get("name") or "Finding")[:512],
                description=f.get("description", "") or "",
                location=f.get("url") or f.get("location") or f.get("file"),
                evidence={"detail": str(f.get("evidence", ""))[:4000]},
                exploitability_score=1.0 if confirmed else 0.5,
                verified=confirmed,
                recommendation=f.get("remediation") or f.get("recommendation"),
                cwe_id=f.get("cwe_id"),
                discovered_by_stage=(f.get("source") or stage)[:32],
            ))
        await db.commit()
    except Exception as e:
        print(f"[pipeline] DB persist failed: {e}")


class SupervisorV2:
    """Back-compat shim - delegates to run_pipeline (the real engines)."""

    def __init__(self, target: str, target_type: str = "repo",
                 scan_id: int | None = None, db_session=None, progress_cb=None):
        self.target = target
        self.target_type = target_type
        self.scan_id = scan_id
        self.db = db_session
        self.progress_cb = progress_cb

    async def run(self) -> PipelineResult:
        return await run_pipeline(self.target, self.target_type,
                                  self.scan_id, self.db, self.progress_cb)
