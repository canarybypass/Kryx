"""
Hexor Supervisor — главный оркестратор многоагентной системы
"""
import json
import asyncio
from dataclasses import dataclass, field
from utils.llm import get_llm
from core.agents.prompts import RECON_PROMPT
from core.harness.recon import ReconStage
from core.harness.hunter import HunterStage
from core.harness.validator import ValidatorStage
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

    def __init__(self, target: str, max_hunters: int = 8, progress_cb=None):
        self.target = target
        self.max_hunters = max_hunters
        self.progress_cb = progress_cb  # async callback for WebSocket updates
        self.result = ScanResult(target=target)

    async def run(self) -> dict:
        await self._emit("status", "recon")

        # Stage 1: Reconnaissance
        recon = ReconStage(self.target)
        self.result.recon = await recon.run()
        await self._emit("status", "hunting")
        await self._emit("recon", self.result.recon)

        # Stage 2: Parallel hunting
        hunter = HunterStage(self.target, self.result.recon, self.max_hunters, self._emit)
        self.result.findings = await hunter.run()
        await self._emit("findings_raw", self.result.findings)

        # Stage 3: Adversarial validation
        validator = ValidatorStage(self.target, self.result.recon, self.result.findings)
        self.result.validated_findings = await validator.run()
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