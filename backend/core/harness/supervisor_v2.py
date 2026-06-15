"""
Kryx Supervisor v2 — 6-Stage Pipeline Orchestrator

New architecture for 0-day hunting:
1. Static Analysis (AST parsing, taint analysis)
2. Fuzzing Orchestrator (AFL++, libFuzzer)
3. Variant Hunter (find similar bugs)
4. Exploit Builder (ROP, heap spray, etc)
5. Chain Constructor (multi-vuln chains)
6. Verification (sandbox testing)
"""
import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Callable

from core.harness.static_analyzer import run_static_analysis, StaticFinding, CodeLocation
from db import Scan, Vulnerability, AttackChain, ScanStatus, VulnerabilitySeverity, VulnerabilityType


@dataclass
class PipelineResult:
    """Results from entire 6-stage pipeline"""
    target: str
    target_type: str  # web|repo|binary|source
    
    # Stage results
    static_findings: list[StaticFinding] = field(default_factory=list)
    fuzzing_crashes: list = field(default_factory=list)
    variants: list = field(default_factory=list)
    exploits: list = field(default_factory=list)
    attack_chains: list = field(default_factory=list)
    verified_exploits: list = field(default_factory=list)
    
    # Metadata
    summary: str = ""
    report: str = ""
    stats: dict = field(default_factory=dict)
    
    # Timing
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class SupervisorV2:
    """
    New 6-stage pipeline orchestrator for 0-day hunting.
    
    Designed for:
    - Source code repositories
    - Binary analysis
    - Web application scanning
    - Firmware analysis
    """
    
    def __init__(
        self,
        target: str,
        target_type: str = "repo",  # web|repo|binary|source
        scan_id: Optional[int] = None,
        db_session=None,
        progress_callback: Optional[Callable] = None
    ):
        self.target = target
        self.target_type = target_type
        self.scan_id = scan_id
        self.db = db_session
        self.progress_cb = progress_callback
        
        self.result = PipelineResult(
            target=target,
            target_type=target_type,
            started_at=datetime.utcnow()
        )
    
    async def run(self) -> PipelineResult:
        """
        Execute full 6-stage pipeline.
        
        Returns complete results with all findings, exploits, chains.
        """
        try:
            await self._emit("pipeline_started", {"target": self.target})
            
            # Stage 1: Static Analysis
            await self._run_static_analysis()
            
            # Stage 2: Fuzzing (if applicable)
            if self.target_type in ["binary", "source", "repo"]:
                await self._run_fuzzing()
            
            # Stage 3: Variant Hunter
            await self._run_variant_hunter()
            
            # Stage 4: Exploit Builder
            await self._run_exploit_builder()
            
            # Stage 5: Chain Constructor
            await self._run_chain_constructor()
            
            # Stage 6: Verification
            await self._run_verification()
            
            # Generate summary and report
            await self._generate_report()
            
            self.result.finished_at = datetime.utcnow()
            
            # Update database
            if self.db and self.scan_id:
                await self._save_to_db()
            
            await self._emit("pipeline_completed", {
                "total_vulns": len(self.result.static_findings),
                "exploits": len(self.result.exploits),
                "chains": len(self.result.attack_chains)
            })
            
            return self.result
        
        except Exception as e:
            await self._emit("pipeline_failed", {"error": str(e)})
            raise
    
    async def _run_static_analysis(self):
        """Stage 1: Static code analysis"""
        await self._emit("stage_started", {"stage": "static_analysis"})
        await self._update_scan_status(static_analysis_done=False)
        
        try:
            # Determine project path
            project_path = self._get_project_path()
            
            # Run static analyzer
            findings = await run_static_analysis(project_path)
            
            self.result.static_findings = findings
            
            await self._update_scan_status(static_analysis_done=True)
            await self._emit("stage_completed", {
                "stage": "static_analysis",
                "findings_count": len(findings),
                "critical": len([f for f in findings if f.severity == "critical"]),
                "high": len([f for f in findings if f.severity == "high"])
            })
            
            print(f"[Stage 1] Static Analysis: {len(findings)} findings")
        
        except Exception as e:
            print(f"[Stage 1] Static Analysis failed: {e}")
            await self._emit("stage_failed", {"stage": "static_analysis", "error": str(e)})
    
    async def _run_fuzzing(self):
        """Stage 2: Fuzzing orchestration"""
        await self._emit("stage_started", {"stage": "fuzzing"})
        await self._update_scan_status(fuzzing_done=False)
        
        try:
            # TODO: Implement fuzzing orchestrator
            # Will integrate AFL++, libFuzzer, Syzkaller
            
            print("[Stage 2] Fuzzing: Not implemented yet")
            
            await self._update_scan_status(fuzzing_done=True)
            await self._emit("stage_completed", {"stage": "fuzzing", "crashes": 0})
        
        except Exception as e:
            print(f"[Stage 2] Fuzzing failed: {e}")
            await self._emit("stage_failed", {"stage": "fuzzing", "error": str(e)})
    
    async def _run_variant_hunter(self):
        """Stage 3: Find similar vulnerabilities"""
        await self._emit("stage_started", {"stage": "variant_hunter"})
        await self._update_scan_status(variant_hunt_done=False)
        
        try:
            from core.harness.variant_hunter import find_variants
            
            # Only run if we have static findings
            if not self.result.static_findings:
                print("[Stage 3] Variant Hunter: No findings to hunt variants for")
                await self._update_scan_status(variant_hunt_done=True)
                return
            
            project_path = self._get_project_path()
            
            # Hunt variants for top severity findings only
            high_severity = [
                f for f in self.result.static_findings 
                if f.severity in ["critical", "high"]
            ][:5]  # Top 5 to avoid API cost explosion
            
            all_variants = []
            
            for finding in high_severity:
                print(f"[Stage 3] Hunting variants for: {finding.name}")
                
                variants = await find_variants(
                    project_path,
                    finding.location.snippet,
                    f"{finding.location.file}:{finding.location.line}",
                    finding.vuln_type
                )
                
                # Convert to StaticFinding format
                for variant in variants:
                    variant_finding = StaticFinding(
                        vuln_type=finding.vuln_type,
                        severity=finding.severity,
                        name=f"Variant: {variant.fragment.function_name} (similar to {finding.name})",
                        description=variant.description or f"Similar vulnerability found via variant analysis",
                        location=CodeLocation(
                            file=variant.fragment.file,
                            line=variant.fragment.start_line,
                            column=0,
                            snippet=variant.fragment.code[:200]
                        ),
                        confidence=variant.confidence,
                        evidence={
                            "variant_of": finding.name,
                            "similarity_score": variant.similarity_score,
                            "similarity_reason": variant.similarity_reason
                        },
                        cwe_id=finding.cwe_id
                    )
                    all_variants.append(variant_finding)
                
                await self._emit("variant_found", {
                    "original": finding.name,
                    "variants_count": len(variants)
                })
            
            self.result.variants = all_variants
            
            # Add variants to static findings
            self.result.static_findings.extend(all_variants)
            
            await self._update_scan_status(variant_hunt_done=True)
            await self._emit("stage_completed", {
                "stage": "variant_hunter",
                "variants": len(all_variants)
            })
            
            print(f"[Stage 3] Variant Hunter: Found {len(all_variants)} variants")
        
        except Exception as e:
            print(f"[Stage 3] Variant Hunter failed: {e}")
            await self._emit("stage_failed", {"stage": "variant_hunter", "error": str(e)})
    
    async def _run_exploit_builder(self):
        """Stage 4: Build exploits for findings"""
        await self._emit("stage_started", {"stage": "exploit_builder"})
        await self._update_scan_status(exploit_build_done=False)
        
        try:
            from knowledge.knowledge_base import KnowledgeBase
            
            # Only build exploits for high/critical findings
            high_severity = [
                f for f in self.result.static_findings
                if f.severity in ["critical", "high"]
            ][:5]
            
            if not high_severity:
                print("[Stage 4] Exploit Builder: No high-severity findings")
                await self._update_scan_status(exploit_build_done=True)
                return
            
            kb = KnowledgeBase(self.db) if self.db else None
            exploits = []
            
            for finding in high_severity:
                print(f"[Stage 4] Building exploit for: {finding.name}")
                
                # Get exploit template from knowledge base
                if kb:
                    template = await kb.get_exploit_template(
                        self._map_vuln_type(finding.vuln_type)
                    )
                    
                    if template:
                        # Generate exploit code from template
                        exploit_code = self._generate_exploit(finding, template)
                        
                        exploit = {
                            "name": f"Exploit for {finding.name}",
                            "vulnerability": finding.name,
                            "technique": template.technique,
                            "code": exploit_code,
                            "language": template.language
                        }
                        exploits.append(exploit)
                        
                        await self._emit("exploit_generated", {
                            "vuln": finding.name,
                            "technique": template.technique
                        })
            
            self.result.exploits = exploits
            
            await self._update_scan_status(exploit_build_done=True)
            await self._emit("stage_completed", {
                "stage": "exploit_builder",
                "exploits": len(exploits)
            })
            
            print(f"[Stage 4] Exploit Builder: {len(exploits)} exploits generated")
        
        except Exception as e:
            print(f"[Stage 4] Exploit Builder failed: {e}")
            await self._emit("stage_failed", {"stage": "exploit_builder", "error": str(e)})
    
    def _generate_exploit(self, finding, template) -> str:
        """Generate exploit code from template and finding"""
        code = template.code_template
        
        # Simple placeholder substitution
        code = code.replace("{target}", finding.location.file)
        code = code.replace("{vuln_description}", finding.description[:100])
        code = code.replace("{offset}", "64")  # Default offset
        
        return code
    
    async def _run_chain_constructor(self):
        """Stage 5: Build multi-vulnerability attack chains"""
        await self._emit("stage_started", {"stage": "chain_constructor"})
        
        try:
            # TODO: Implement chain constructor
            # Combine vulns into APT-level chains
            
            print("[Stage 5] Chain Constructor: Not implemented yet")
            
            await self._emit("stage_completed", {"stage": "chain_constructor", "chains": 0})
        
        except Exception as e:
            print(f"[Stage 5] Chain Constructor failed: {e}")
            await self._emit("stage_failed", {"stage": "chain_constructor", "error": str(e)})
    
    async def _run_verification(self):
        """Stage 6: Verify exploits in sandbox"""
        await self._emit("stage_started", {"stage": "verification"})
        await self._update_scan_status(verification_done=False)
        
        try:
            from core.sandbox.executor import create_sandbox
            
            # Only verify if we have exploits
            if not self.result.exploits:
                print("[Stage 6] Verification: No exploits to verify")
                await self._update_scan_status(verification_done=True)
                return
            
            sandbox = create_sandbox()
            verified = []
            
            for exploit in self.result.exploits[:5]:  # Verify top 5
                print(f"[Stage 6] Verifying exploit: {exploit.get('name')}")
                
                result = await sandbox.execute_exploit(
                    exploit_code=exploit.get("code", ""),
                    timeout=30
                )
                
                if result.get("exploit_success"):
                    verified.append(exploit)
                    await self._emit("exploit_verified", {
                        "exploit": exploit.get("name"),
                        "success": True
                    })
            
            self.result.verified_exploits = verified
            
            await self._update_scan_status(verification_done=True)
            await self._emit("stage_completed", {
                "stage": "verification",
                "verified": len(verified)
            })
            
            print(f"[Stage 6] Verification: {len(verified)} exploits verified")
        
        except Exception as e:
            print(f"[Stage 6] Verification failed: {e}")
            await self._emit("stage_failed", {"stage": "verification", "error": str(e)})
    
    async def _generate_report(self):
        """Generate final report and summary"""
        total = len(self.result.static_findings)
        critical = len([f for f in self.result.static_findings if f.severity == "critical"])
        high = len([f for f in self.result.static_findings if f.severity == "high"])
        
        self.result.summary = (
            f"Found {total} vulnerabilities: "
            f"{critical} critical, {high} high severity"
        )
        
        # TODO: Generate detailed markdown report
        self.result.report = f"# Security Audit Report\n\nTarget: {self.target}\n\n"
        
        self.result.stats = {
            "total_findings": total,
            "by_severity": {
                "critical": critical,
                "high": high,
                "medium": len([f for f in self.result.static_findings if f.severity == "medium"]),
                "low": len([f for f in self.result.static_findings if f.severity == "low"])
            },
            "by_type": self._count_by_type(),
            "exploits_generated": len(self.result.exploits),
            "attack_chains": len(self.result.attack_chains)
        }
    
    def _count_by_type(self) -> dict:
        """Count findings by vulnerability type"""
        counts = {}
        for finding in self.result.static_findings:
            vtype = finding.vuln_type
            counts[vtype] = counts.get(vtype, 0) + 1
        return counts
    
    def _get_project_path(self) -> str:
        """Get filesystem path to analyze"""
        # TODO: Handle different target types
        # - repo: clone from git
        # - source: use provided path
        # - binary: extract to temp dir
        # - web: N/A for static analysis
        
        if self.target_type == "source":
            return self.target
        
        # For now, assume it's a path
        return self.target
    
    async def _save_to_db(self):
        """Save results to database"""
        if not self.db or not self.scan_id:
            return
        
        try:
            # Get scan from DB
            scan = await self.db.get(Scan, self.scan_id)
            if not scan:
                return
            
            # Update scan
            scan.status = ScanStatus.COMPLETED
            scan.summary = self.result.summary
            scan.report = self.result.report
            scan.stats = self.result.stats
            scan.finished_at = self.result.finished_at
            
            # Save vulnerabilities
            for finding in self.result.static_findings:
                vuln = Vulnerability(
                    scan_id=scan.id,
                    organization_id=scan.organization_id,
                    vuln_type=self._map_vuln_type(finding.vuln_type),
                    severity=self._map_severity(finding.severity),
                    name=finding.name,
                    description=finding.description,
                    location=f"{finding.location.file}:{finding.location.line}",
                    evidence=finding.evidence,
                    exploitability_score=finding.confidence,
                    cwe_id=finding.cwe_id,
                    recommendation=finding.recommendation,
                    discovered_by_stage="static"
                )
                self.db.add(vuln)
            
            await self.db.commit()
        
        except Exception as e:
            print(f"[DB] Failed to save results: {e}")
    
    async def _update_scan_status(self, **kwargs):
        """Update scan stage completion flags"""
        if not self.db or not self.scan_id:
            return
        
        try:
            scan = await self.db.get(Scan, self.scan_id)
            if scan:
                for key, value in kwargs.items():
                    setattr(scan, key, value)
                await self.db.commit()
        except Exception as e:
            print(f"[DB] Failed to update scan status: {e}")
    
    def _map_vuln_type(self, vtype: str) -> VulnerabilityType:
        """Map string vuln type to enum"""
        mapping = {
            "memory_corruption": VulnerabilityType.MEMORY_CORRUPTION,
            "injection": VulnerabilityType.INJECTION,
            "xss": VulnerabilityType.XSS,
            "csrf": VulnerabilityType.CSRF,
            "auth_bypass": VulnerabilityType.AUTH_BYPASS,
            "info_disclosure": VulnerabilityType.INFO_DISCLOSURE,
        }
        return mapping.get(vtype, VulnerabilityType.OTHER)
    
    def _map_severity(self, severity: str) -> VulnerabilitySeverity:
        """Map string severity to enum"""
        mapping = {
            "critical": VulnerabilitySeverity.CRITICAL,
            "high": VulnerabilitySeverity.HIGH,
            "medium": VulnerabilitySeverity.MEDIUM,
            "low": VulnerabilitySeverity.LOW,
            "info": VulnerabilitySeverity.INFO,
        }
        return mapping.get(severity, VulnerabilitySeverity.INFO)
    
    async def _emit(self, event: str, data: dict):
        """Emit progress event via callback"""
        if self.progress_cb:
            try:
                await self.progress_cb({"event": event, "data": data})
            except Exception as e:
                print(f"[Progress] Callback error: {e}")


# Convenience function
async def run_pipeline(target: str, target_type: str = "repo", scan_id: int = None, db_session=None) -> PipelineResult:
    """Run full 6-stage pipeline"""
    supervisor = SupervisorV2(target, target_type, scan_id, db_session)
    return await supervisor.run()
