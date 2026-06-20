"""
Kryx Knowledge Base — Vulnerability Database

Stores and queries:
- Known vulnerability patterns
- CVE mappings
- Exploit templates
- Similar vulnerabilities
- Attack techniques

Data sources:
- Exploit-DB
- GitHub Security Advisories
- NVD CVE database
- Internal findings
"""
from typing import List, Dict, Optional
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_

from db import VulnerabilityPattern, ExploitTemplate, Vulnerability, VulnerabilityType


class KnowledgeBase:
    """
    Vulnerability knowledge base for pattern matching and exploit generation.
    
    Features:
    - Pattern library for detection
    - Exploit template library
    - CVE lookup
    - Similar vulnerability search
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def add_pattern(
        self,
        pattern_name: str,
        vuln_type: VulnerabilityType,
        code_signature: Optional[str] = None,
        ast_pattern: Optional[Dict] = None,
        severity: str = "medium",
        examples: Optional[List[str]] = None,
        cve_references: Optional[List[str]] = None
    ) -> int:
        """
        Add vulnerability pattern to knowledge base.
        
        Args:
            pattern_name: Human-readable pattern name
            vuln_type: Type of vulnerability
            code_signature: Regex or string pattern
            ast_pattern: AST structure pattern (dict)
            severity: Default severity for this pattern
            examples: Example code snippets
            cve_references: Related CVE IDs
        
        Returns:
            Pattern ID
        """
        from db import VulnerabilityPattern, VulnerabilitySeverity
        
        pattern = VulnerabilityPattern(
            pattern_name=pattern_name,
            vuln_type=vuln_type,
            code_signature=code_signature,
            ast_pattern=ast_pattern,
            examples=examples,
            cve_references=cve_references,
            severity=VulnerabilitySeverity(severity),
            false_positive_rate=0.1  # Default estimate
        )
        
        self.db.add(pattern)
        await self.db.commit()
        await self.db.refresh(pattern)
        
        return pattern.id
    
    async def search_patterns(
        self,
        query: str,
        vuln_type: Optional[VulnerabilityType] = None,
        limit: int = 10
    ) -> List[VulnerabilityPattern]:
        """
        Search for vulnerability patterns.
        
        Args:
            query: Search query (pattern name or code signature)
            vuln_type: Filter by type
            limit: Max results
        
        Returns:
            List of matching patterns
        """
        stmt = select(VulnerabilityPattern)
        
        # Text search
        if query:
            stmt = stmt.where(
                or_(
                    VulnerabilityPattern.pattern_name.ilike(f"%{query}%"),
                    VulnerabilityPattern.code_signature.ilike(f"%{query}%")
                )
            )
        
        # Filter by type
        if vuln_type:
            stmt = stmt.where(VulnerabilityPattern.vuln_type == vuln_type)
        
        stmt = stmt.limit(limit)
        
        result = await self.db.execute(stmt)
        return result.scalars().all()
    
    async def add_exploit_template(
        self,
        name: str,
        vuln_type: VulnerabilityType,
        technique: str,
        language: str,
        code_template: str,
        description: Optional[str] = None,
        requirements: Optional[List[str]] = None
    ) -> int:
        """
        Add exploit template to knowledge base.
        
        Args:
            name: Template name
            vuln_type: Vulnerability type this exploits
            technique: Exploitation technique (ROP, heap_spray, etc)
            language: Template language (python, c, javascript)
            code_template: Template code with placeholders
            description: What this template does
            requirements: List of preconditions
        
        Returns:
            Template ID
        """
        template = ExploitTemplate(
            name=name,
            vuln_type=vuln_type,
            technique=technique,
            language=language,
            code_template=code_template,
            description=description,
            requirements=requirements,
            times_used=0,
            times_successful=0
        )
        
        self.db.add(template)
        await self.db.commit()
        await self.db.refresh(template)
        
        return template.id
    
    async def get_exploit_template(
        self,
        vuln_type: VulnerabilityType,
        technique: Optional[str] = None
    ) -> Optional[ExploitTemplate]:
        """
        Get best exploit template for vulnerability type.
        
        Returns template with highest success rate.
        """
        stmt = select(ExploitTemplate).where(
            ExploitTemplate.vuln_type == vuln_type
        )
        
        if technique:
            stmt = stmt.where(ExploitTemplate.technique == technique)
        
        # Order by success rate
        stmt = stmt.order_by(
            (ExploitTemplate.times_successful / 
             func.greatest(ExploitTemplate.times_used, 1)).desc()
        ).limit(1)
        
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()
    
    async def record_exploit_usage(
        self,
        template_id: int,
        success: bool
    ) -> None:
        """Record exploit template usage for statistics"""
        template = await self.db.get(ExploitTemplate, template_id)
        
        if template:
            template.times_used += 1
            if success:
                template.times_successful += 1
            
            await self.db.commit()
    
    async def find_similar_vulns(
        self,
        vuln_id: int,
        threshold: float = 0.7,
        limit: int = 10
    ) -> List[Dict]:
        """
        Find similar vulnerabilities to given one.
        
        Uses:
        - Vulnerability type
        - Code location patterns
        - CWE IDs
        
        Args:
            vuln_id: Reference vulnerability ID
            threshold: Similarity threshold (0.0-1.0)
            limit: Max results
        
        Returns:
            List of similar vulnerabilities with similarity scores
        """
        # Get reference vulnerability
        ref_vuln = await self.db.get(Vulnerability, vuln_id)
        if not ref_vuln:
            return []
        
        # Find similar by type and CWE
        stmt = select(Vulnerability).where(
            Vulnerability.id != vuln_id,
            or_(
                Vulnerability.vuln_type == ref_vuln.vuln_type,
                Vulnerability.cwe_id == ref_vuln.cwe_id
            )
        ).limit(limit)
        
        result = await self.db.execute(stmt)
        similar = result.scalars().all()
        
        # Calculate similarity scores (simple heuristic)
        results = []
        for vuln in similar:
            score = 0.0
            
            # Same type
            if vuln.vuln_type == ref_vuln.vuln_type:
                score += 0.5
            
            # Same CWE
            if vuln.cwe_id and vuln.cwe_id == ref_vuln.cwe_id:
                score += 0.3
            
            # Same severity
            if vuln.severity == ref_vuln.severity:
                score += 0.2
            
            if score >= threshold:
                results.append({
                    "vulnerability": vuln,
                    "similarity_score": score
                })
        
        # Sort by score
        results.sort(key=lambda x: x["similarity_score"], reverse=True)
        
        return results
    
    async def lookup_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Lookup CVE information.
        
        Returns CVE details from internal DB or external API.
        """
        # Check internal database first
        stmt = select(Vulnerability).where(Vulnerability.cve_id == cve_id)
        result = await self.db.execute(stmt)
        vuln = result.scalar_one_or_none()
        
        if vuln:
            return {
                "cve_id": vuln.cve_id,
                "severity": vuln.severity,
                "description": vuln.description,
                "cwe_id": vuln.cwe_id,
                "source": "internal"
            }
        
        # TODO: Query NVD API for external CVE data
        return None
    
    async def get_stats(self) -> Dict:
        """Get knowledge base statistics"""
        from sqlalchemy import func
        
        # Count patterns
        patterns_result = await self.db.execute(
            select(func.count(VulnerabilityPattern.id))
        )
        patterns_count = patterns_result.scalar()
        
        # Count templates
        templates_result = await self.db.execute(
            select(func.count(ExploitTemplate.id))
        )
        templates_count = templates_result.scalar()
        
        # Count vulnerabilities
        vulns_result = await self.db.execute(
            select(func.count(Vulnerability.id))
        )
        vulns_count = vulns_result.scalar()
        
        # Count by type
        by_type_result = await self.db.execute(
            select(
                Vulnerability.vuln_type,
                func.count(Vulnerability.id)
            ).group_by(Vulnerability.vuln_type)
        )
        
        by_type = {str(row[0]): row[1] for row in by_type_result}
        
        return {
            "patterns": patterns_count,
            "exploit_templates": templates_count,
            "vulnerabilities": vulns_count,
            "by_type": by_type,
            "last_updated": datetime.utcnow().isoformat()
        }


async def seed_knowledge_base(db: AsyncSession) -> None:
    """
    Seed knowledge base with common patterns and templates.
    
    Call this during initial setup.
    """
    kb = KnowledgeBase(db)
    
    # Add common patterns
    patterns = [
        {
            "pattern_name": "strcpy buffer overflow",
            "vuln_type": VulnerabilityType.MEMORY_CORRUPTION,
            "code_signature": r"strcpy\s*\(",
            "severity": "high",
            "examples": ["strcpy(buffer, user_input);"],
            "cve_references": ["CVE-2021-3156"]  # Example
        },
        {
            "pattern_name": "SQL injection via concatenation",
            "vuln_type": VulnerabilityType.INJECTION,
            "code_signature": r"(execute|query).*\+.*\$_(GET|POST)",
            "severity": "critical",
            "examples": ["query = 'SELECT * FROM users WHERE id=' + $_GET['id']"]
        },
        {
            "pattern_name": "eval() code execution",
            "vuln_type": VulnerabilityType.INJECTION,
            "code_signature": r"\beval\s*\(",
            "severity": "critical",
            "examples": ["eval(user_input)"]
        },
        {
            "pattern_name": "innerHTML XSS",
            "vuln_type": VulnerabilityType.XSS,
            "code_signature": r"\.innerHTML\s*=",
            "severity": "high",
            "examples": ["element.innerHTML = user_input"]
        }
    ]
    
    for pattern_data in patterns:
        try:
            await kb.add_pattern(**pattern_data)
        except Exception as e:
            print(f"[KB] Pattern already exists or error: {e}")
    
    # Add exploit templates
    templates = [
        {
            "name": "Python ROP Chain Generator",
            "vuln_type": VulnerabilityType.MEMORY_CORRUPTION,
            "technique": "ROP",
            "language": "python",
            "code_template": """
import struct

# ROP chain for {target}
# Vulnerability: {vuln_description}

payload = b'A' * {offset}  # Fill buffer
payload += struct.pack('<Q', {gadget1})  # pop rdi; ret
payload += struct.pack('<Q', {bin_sh})   # /bin/sh address
payload += struct.pack('<Q', {system})   # system() address
""",
            "description": "Basic ROP chain to call system('/bin/sh')",
            "requirements": ["Known offsets", "Gadget addresses", "ASLR disabled or leaked"]
        },
        {
            "name": "JavaScript Heap Spray",
            "vuln_type": VulnerabilityType.MEMORY_CORRUPTION,
            "technique": "heap_spray",
            "language": "javascript",
            "code_template": """
// Heap spray for {target}
var spray = unescape('%u{shellcode_hex}');
while (spray.length < 0x100000) spray += spray;

var chunks = [];
for (var i = 0; i < 1000; i++) {
    chunks.push(spray.substring(0, 0x80000));
}
// Trigger vulnerability
{trigger_code}
""",
            "description": "Heap spray to control memory layout",
            "requirements": ["Shellcode", "Trigger primitive"]
        }
    ]
    
    for template_data in templates:
        try:
            await kb.add_exploit_template(**template_data)
        except Exception as e:
            print(f"[KB] Template already exists or error: {e}")
    
    print("[KB] Knowledge base seeded successfully")
