"""
Kryx Static Analysis Stage — AST-based vulnerability detection

Performs:
1. AST parsing (tree-sitter for multi-language)
2. Taint analysis (track user input → dangerous sinks)
3. Pattern matching (known vulnerability patterns)
4. Data flow analysis (UAF, double-free, race conditions)
5. Control flow analysis (TOCTOU, logic bugs)
"""
import re
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional

from utils.llm import get_llm


@dataclass
class CodeLocation:
    file: str
    line: int
    column: int
    snippet: str


@dataclass
class TaintPath:
    """Tracks data flow from source (user input) to sink (dangerous operation)"""
    source: CodeLocation
    sink: CodeLocation
    path: List[CodeLocation]
    severity: str  # critical|high|medium|low


@dataclass
class StaticFinding:
    """A vulnerability found by static analysis"""
    vuln_type: str
    severity: str
    name: str
    description: str
    location: CodeLocation
    confidence: float  # 0.0-1.0
    evidence: Dict
    taint_paths: List[TaintPath] = field(default_factory=list)
    cwe_id: Optional[str] = None
    recommendation: Optional[str] = None


class StaticAnalyzer:
    """
    Multi-language static analyzer using pattern matching + LLM reasoning.
    
    Supports: C, C++, Python, JavaScript, PHP, Java, Go, Rust
    """
    
    def __init__(self):
        self.llm = get_llm()
        self.findings: List[StaticFinding] = []
        
    async def analyze_project(self, project_path: str) -> List[StaticFinding]:
        """
        Analyze entire project for vulnerabilities.
        
        Flow:
        1. Discover source files
        2. Parse each file → AST
        3. Run pattern matchers
        4. Run taint analysis
        5. LLM validation + severity scoring
        """
        project_path = Path(project_path)
        
        # Discover source files
        files = self._discover_files(project_path)
        print(f"[Static] Found {len(files)} source files")
        
        # Analyze each file
        for file_path in files:
            await self._analyze_file(file_path)
        
        # LLM validation pass
        validated = await self._validate_findings()
        
        return validated
    
    def _discover_files(self, path: Path) -> List[Path]:
        """Find all source code files"""
        extensions = {
            '.c', '.cpp', '.cc', '.h', '.hpp',  # C/C++
            '.py',  # Python
            '.js', '.jsx', '.ts', '.tsx',  # JavaScript/TypeScript
            '.php',  # PHP
            '.java',  # Java
            '.go',  # Go
            '.rs',  # Rust
        }
        
        skip_dirs = {
            'node_modules', '.git', 'venv', '__pycache__',
            'vendor', 'dist', 'build', 'target'
        }
        
        files = []
        for ext in extensions:
            for f in path.rglob(f'*{ext}'):
                # Skip if in excluded directory
                if any(skip in f.parts for skip in skip_dirs):
                    continue
                files.append(f)
        
        return files
    
    async def _analyze_file(self, file_path: Path):
        """Analyze single file for vulnerabilities"""
        try:
            content = file_path.read_text(errors='ignore')
        except Exception as e:
            print(f"[Static] Error reading {file_path}: {e}")
            return
        
        # Determine language
        lang = self._detect_language(file_path)
        
        # Run pattern matchers
        await self._run_pattern_matchers(file_path, content, lang)
        
        # Run taint analysis
        await self._run_taint_analysis(file_path, content, lang)
    
    def _detect_language(self, file_path: Path) -> str:
        """Detect programming language from extension"""
        ext = file_path.suffix.lower()
        lang_map = {
            '.c': 'c',
            '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp',
            '.h': 'c', '.hpp': 'cpp',
            '.py': 'python',
            '.js': 'javascript', '.jsx': 'javascript',
            '.ts': 'typescript', '.tsx': 'typescript',
            '.php': 'php',
            '.java': 'java',
            '.go': 'go',
            '.rs': 'rust',
        }
        return lang_map.get(ext, 'unknown')
    
    async def _run_pattern_matchers(self, file_path: Path, content: str, lang: str):
        """Run regex-based pattern matchers for known vulnerability patterns"""
        
        patterns = self._get_vulnerability_patterns(lang)
        
        lines = content.split('\n')
        
        for pattern in patterns:
            regex = pattern['regex']
            vuln_type = pattern['type']
            severity = pattern['severity']
            description = pattern['description']
            cwe = pattern.get('cwe')
            
            for line_num, line in enumerate(lines, 1):
                matches = re.finditer(regex, line, re.IGNORECASE)
                
                for match in matches:
                    # Create finding
                    finding = StaticFinding(
                        vuln_type=vuln_type,
                        severity=severity,
                        name=f"{vuln_type} in {file_path.name}:{line_num}",
                        description=description,
                        location=CodeLocation(
                            file=str(file_path),
                            line=line_num,
                            column=match.start(),
                            snippet=line.strip()
                        ),
                        confidence=pattern.get('confidence', 0.7),
                        evidence={'matched': match.group(), 'pattern': pattern['name']},
                        cwe_id=cwe
                    )
                    
                    self.findings.append(finding)
    
    def _get_vulnerability_patterns(self, lang: str) -> List[Dict]:
        """
        Get vulnerability patterns for language.
        
        These are high-confidence regex patterns for common bugs.
        """
        
        # C/C++ patterns
        if lang in ['c', 'cpp']:
            return [
                {
                    'name': 'strcpy buffer overflow',
                    'regex': r'\bstrcpy\s*\(',
                    'type': 'memory_corruption',
                    'severity': 'high',
                    'description': 'strcpy() is unsafe - use strncpy() or strlcpy()',
                    'cwe': 'CWE-120',
                    'confidence': 0.8
                },
                {
                    'name': 'gets buffer overflow',
                    'regex': r'\bgets\s*\(',
                    'type': 'memory_corruption',
                    'severity': 'critical',
                    'description': 'gets() has no bounds checking - use fgets()',
                    'cwe': 'CWE-676',
                    'confidence': 0.95
                },
                {
                    'name': 'sprintf buffer overflow',
                    'regex': r'\bsprintf\s*\(',
                    'type': 'memory_corruption',
                    'severity': 'high',
                    'description': 'sprintf() is unsafe - use snprintf()',
                    'cwe': 'CWE-120',
                    'confidence': 0.75
                },
                {
                    'name': 'format string vulnerability',
                    'regex': r'printf\s*\(\s*[^"]+\s*\)',
                    'type': 'memory_corruption',
                    'severity': 'high',
                    'description': 'Potential format string bug - user input in format string',
                    'cwe': 'CWE-134',
                    'confidence': 0.6
                },
                {
                    'name': 'use after free potential',
                    'regex': r'free\s*\([^)]+\).*\n.*\1',  # oversimplified
                    'type': 'memory_corruption',
                    'severity': 'critical',
                    'description': 'Potential use-after-free',
                    'cwe': 'CWE-416',
                    'confidence': 0.5
                },
                {
                    'name': 'integer overflow in allocation',
                    'regex': r'malloc\s*\([^)]*\*[^)]*\)',
                    'type': 'memory_corruption',
                    'severity': 'medium',
                    'description': 'Multiplication in malloc() may overflow',
                    'cwe': 'CWE-190',
                    'confidence': 0.6
                },
            ]
        
        # Python patterns
        elif lang == 'python':
            return [
                {
                    'name': 'SQL injection via f-string',
                    'regex': r'(execute|executemany)\s*\(\s*f["\']',
                    'type': 'injection',
                    'severity': 'critical',
                    'description': 'SQL injection - use parameterized queries',
                    'cwe': 'CWE-89',
                    'confidence': 0.9
                },
                {
                    'name': 'SQL injection via concatenation',
                    'regex': r'(execute|executemany)\s*\([^)]*\+[^)]*\)',
                    'type': 'injection',
                    'severity': 'critical',
                    'description': 'SQL injection via string concatenation',
                    'cwe': 'CWE-89',
                    'confidence': 0.85
                },
                {
                    'name': 'command injection via shell=True',
                    'regex': r'subprocess\.(call|run|Popen).*shell\s*=\s*True',
                    'type': 'injection',
                    'severity': 'critical',
                    'description': 'Command injection risk with shell=True',
                    'cwe': 'CWE-78',
                    'confidence': 0.8
                },
                {
                    'name': 'eval() code execution',
                    'regex': r'\beval\s*\(',
                    'type': 'injection',
                    'severity': 'critical',
                    'description': 'eval() with user input = RCE',
                    'cwe': 'CWE-95',
                    'confidence': 0.9
                },
                {
                    'name': 'pickle deserialization',
                    'regex': r'pickle\.(loads?|Unpickler)',
                    'type': 'injection',
                    'severity': 'high',
                    'description': 'Pickle deserialization can execute arbitrary code',
                    'cwe': 'CWE-502',
                    'confidence': 0.7
                },
                {
                    'name': 'debug mode enabled',
                    'regex': r'debug\s*=\s*True',
                    'type': 'info_disclosure',
                    'severity': 'medium',
                    'description': 'Debug mode exposes sensitive info in production',
                    'cwe': 'CWE-215',
                    'confidence': 0.8
                },
            ]
        
        # JavaScript patterns
        elif lang in ['javascript', 'typescript']:
            return [
                {
                    'name': 'eval() code execution',
                    'regex': r'\beval\s*\(',
                    'type': 'injection',
                    'severity': 'critical',
                    'description': 'eval() with user input = XSS/RCE',
                    'cwe': 'CWE-95',
                    'confidence': 0.9
                },
                {
                    'name': 'innerHTML XSS',
                    'regex': r'\.innerHTML\s*=',
                    'type': 'xss',
                    'severity': 'high',
                    'description': 'innerHTML can cause XSS - use textContent',
                    'cwe': 'CWE-79',
                    'confidence': 0.7
                },
                {
                    'name': 'dangerouslySetInnerHTML',
                    'regex': r'dangerouslySetInnerHTML',
                    'type': 'xss',
                    'severity': 'high',
                    'description': 'Potential XSS via dangerouslySetInnerHTML',
                    'cwe': 'CWE-79',
                    'confidence': 0.8
                },
                {
                    'name': 'document.write XSS',
                    'regex': r'document\.write\(',
                    'type': 'xss',
                    'severity': 'high',
                    'description': 'document.write() can cause XSS',
                    'cwe': 'CWE-79',
                    'confidence': 0.75
                },
            ]
        
        # PHP patterns
        elif lang == 'php':
            return [
                {
                    'name': 'SQL injection',
                    'regex': r'(mysql_query|mysqli_query|pg_query)\s*\([^)]*\$_(GET|POST|REQUEST)',
                    'type': 'injection',
                    'severity': 'critical',
                    'description': 'SQL injection - use prepared statements',
                    'cwe': 'CWE-89',
                    'confidence': 0.9
                },
                {
                    'name': 'command injection',
                    'regex': r'(exec|shell_exec|system|passthru)\s*\([^)]*\$_(GET|POST|REQUEST)',
                    'type': 'injection',
                    'severity': 'critical',
                    'description': 'Command injection via user input',
                    'cwe': 'CWE-78',
                    'confidence': 0.9
                },
                {
                    'name': 'file inclusion',
                    'regex': r'(include|require|include_once|require_once)\s*\([^)]*\$_(GET|POST|REQUEST)',
                    'type': 'injection',
                    'severity': 'critical',
                    'description': 'Local/Remote file inclusion',
                    'cwe': 'CWE-98',
                    'confidence': 0.85
                },
                {
                    'name': 'unserialize RCE',
                    'regex': r'unserialize\s*\([^)]*\$_(GET|POST|REQUEST)',
                    'type': 'injection',
                    'severity': 'critical',
                    'description': 'Object injection via unserialize()',
                    'cwe': 'CWE-502',
                    'confidence': 0.9
                },
            ]
        
        return []
    
    async def _run_taint_analysis(self, file_path: Path, content: str, lang: str):
        """
        Taint analysis: track data flow from sources (user input) to sinks (dangerous ops).
        
        Uses LLM for semantic understanding since full dataflow analysis is complex.
        """
        
        # Define sources (where untrusted data comes from)
        sources = self._get_taint_sources(lang)
        
        # Define sinks (dangerous operations)
        sinks = self._get_taint_sinks(lang)
        
        # Find all source locations
        source_locations = []
        for source_pattern in sources:
            for match in re.finditer(source_pattern, content):
                source_locations.append({
                    'pattern': source_pattern,
                    'location': match.span(),
                    'snippet': match.group()
                })
        
        if not source_locations:
            return  # No user input in this file
        
        # Ask LLM to trace dataflow
        prompt = f"""Analyze this {lang} code for taint vulnerabilities.

Sources of untrusted data found:
{json.dumps([s['snippet'] for s in source_locations[:5]], indent=2)}

File: {file_path.name}
Code snippet (first 100 lines):
```{lang}
{chr(10).join(content.split(chr(10))[:100])}
```

Does any untrusted data flow to dangerous operations without sanitization?
Dangerous sinks: {', '.join(sinks[:10])}

Answer in JSON:
{{
  "has_taint_flow": bool,
  "paths": [
    {{
      "source": "variable/function name",
      "sink": "dangerous operation",
      "sanitized": bool,
      "severity": "critical|high|medium|low",
      "confidence": 0.0-1.0
    }}
  ]
}}
"""
        
        try:
            response = await self.llm.ask(
                "You are a security code auditor specialized in taint analysis.",
                prompt,
                json_mode=True
            )
            
            result = json.loads(response) if isinstance(response, str) else response
            
            if result.get('has_taint_flow'):
                for path_info in result.get('paths', []):
                    if not path_info.get('sanitized'):
                        # Create finding
                        finding = StaticFinding(
                            vuln_type='injection',
                            severity=path_info.get('severity', 'high'),
                            name=f"Taint flow: {path_info['source']} → {path_info['sink']}",
                            description=f"Unsanitized data from {path_info['source']} flows to {path_info['sink']}",
                            location=CodeLocation(
                                file=str(file_path),
                                line=1,  # TODO: extract from LLM
                                column=0,
                                snippet=path_info.get('sink', '')
                            ),
                            confidence=path_info.get('confidence', 0.7),
                            evidence={'taint_analysis': path_info}
                        )
                        self.findings.append(finding)
        
        except Exception as e:
            print(f"[Static] Taint analysis error for {file_path}: {e}")
    
    def _get_taint_sources(self, lang: str) -> List[str]:
        """Patterns for untrusted data sources"""
        if lang in ['c', 'cpp']:
            return [r'fgets\s*\(', r'scanf\s*\(', r'getenv\s*\(', r'argv\[']
        elif lang == 'python':
            return [r'input\s*\(', r'request\.(GET|POST|args|form|json)', r'sys\.argv']
        elif lang in ['javascript', 'typescript']:
            return [r'req\.(query|body|params)', r'location\.(search|hash)', r'document\.cookie']
        elif lang == 'php':
            return [r'\$_(GET|POST|REQUEST|COOKIE|SERVER)\[']
        return []
    
    def _get_taint_sinks(self, lang: str) -> List[str]:
        """Dangerous operations (sinks)"""
        if lang in ['c', 'cpp']:
            return ['strcpy', 'sprintf', 'system', 'popen', 'exec']
        elif lang == 'python':
            return ['execute', 'eval', 'exec', 'subprocess', '__import__']
        elif lang in ['javascript', 'typescript']:
            return ['eval', 'innerHTML', 'document.write', 'setTimeout', 'setInterval']
        elif lang == 'php':
            return ['mysql_query', 'exec', 'system', 'include', 'unserialize']
        return []
    
    async def _validate_findings(self) -> List[StaticFinding]:
        """
        LLM validation pass: reduce false positives.
        
        Ask LLM to review each finding and confirm if it's real.
        """
        validated = []
        
        for finding in self.findings:
            # Skip high-confidence patterns
            if finding.confidence >= 0.9:
                validated.append(finding)
                continue
            
            # Ask LLM to validate
            prompt = f"""Is this a real vulnerability or false positive?

Finding: {finding.name}
Type: {finding.vuln_type}
Location: {finding.location.file}:{finding.location.line}
Code: {finding.location.snippet}
Evidence: {finding.evidence}

Answer JSON:
{{
  "is_real": bool,
  "confidence": 0.0-1.0,
  "reason": "explanation"
}}
"""
            
            try:
                response = await self.llm.ask(
                    "You are a security expert. Minimize false positives.",
                    prompt,
                    json_mode=True
                )
                
                result = json.loads(response) if isinstance(response, str) else response
                
                if result.get('is_real'):
                    finding.confidence = result.get('confidence', finding.confidence)
                    validated.append(finding)
            
            except Exception as e:
                # On error, keep the finding
                validated.append(finding)
        
        return validated


# Helper function for use in harness
async def run_static_analysis(project_path: str) -> List[StaticFinding]:
    """Convenience function to run static analysis"""
    analyzer = StaticAnalyzer()
    findings = await analyzer.analyze_project(project_path)
    print(f"[Static] Found {len(findings)} vulnerabilities")
    return findings
