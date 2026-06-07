"""
Hexor Variant Hunter — Find similar vulnerabilities after initial discovery

Inspired by Google's Big Sleep approach:
When a vulnerability is found, automatically search the codebase for similar patterns.

Example:
  Found: buffer overflow in parse_header_v1()
  Hunt:  parse_header_v2(), parse_header_v3(), all parse_*() functions

Techniques:
1. Function name similarity (regex patterns)
2. Code structure similarity (AST comparison)
3. Semantic similarity (code embeddings)
4. LLM-guided variant search
"""
import re
import asyncio
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from difflib import SequenceMatcher

from utils.llm import get_llm


@dataclass
class CodeFragment:
    """A piece of code that might be vulnerable"""
    file: str
    function_name: str
    start_line: int
    end_line: int
    code: str
    signature: str  # function signature


@dataclass
class VariantCandidate:
    """A potential variant of original vulnerability"""
    fragment: CodeFragment
    similarity_score: float  # 0.0-1.0
    similarity_reason: str
    confidence: float  # 0.0-1.0
    is_vulnerable: Optional[bool] = None
    description: Optional[str] = None


class VariantHunter:
    """
    Searches codebase for variants of known vulnerability.
    
    Strategy:
    1. Analyze original vulnerable code
    2. Extract key patterns (function names, code structure)
    3. Search entire codebase for similar patterns
    4. Rank candidates by similarity
    5. LLM validates top candidates
    """
    
    def __init__(self):
        self.llm = get_llm()
    
    async def hunt_variants(
        self,
        project_path: str,
        vulnerable_code: str,
        vulnerable_location: str,
        vulnerability_type: str
    ) -> List[VariantCandidate]:
        """
        Find variants of vulnerability in codebase.
        
        Args:
            project_path: Path to project root
            vulnerable_code: Original vulnerable code snippet
            vulnerable_location: file:line of original vuln
            vulnerability_type: Type (e.g., "buffer_overflow", "sql_injection")
        
        Returns:
            List of variant candidates, sorted by similarity
        """
        print(f"[Variant Hunter] Searching for variants of {vulnerability_type} in {vulnerable_location}")
        
        # Extract patterns from original vuln
        patterns = self._extract_patterns(vulnerable_code, vulnerable_location)
        
        # Search codebase for similar code
        candidates = await self._search_codebase(project_path, patterns, vulnerability_type)
        
        # Rank by similarity
        candidates.sort(key=lambda c: c.similarity_score, reverse=True)
        
        # LLM validation of top candidates
        top_candidates = candidates[:10]  # Only validate top 10
        validated = await self._validate_candidates(
            top_candidates,
            vulnerable_code,
            vulnerability_type
        )
        
        print(f"[Variant Hunter] Found {len(validated)} likely variants")
        
        return validated
    
    def _extract_patterns(self, code: str, location: str) -> Dict:
        """
        Extract searchable patterns from vulnerable code.
        
        Returns dict with:
        - function_name
        - function_name_pattern (regex)
        - dangerous_functions (strcpy, sprintf, etc)
        - code_structure_markers
        """
        patterns = {
            "function_name": None,
            "function_pattern": None,
            "dangerous_calls": [],
            "code_markers": []
        }
        
        # Extract function name from location or code
        func_match = re.search(r'(\w+)\s*\(', code)
        if func_match:
            func_name = func_match.group(1)
            patterns["function_name"] = func_name
            
            # Generate pattern for similar function names
            # e.g., parse_v1 → parse_v*, parse_*
            base = re.sub(r'(_v\d+|_\d+|[0-9]+)$', '', func_name)
            patterns["function_pattern"] = f"{base}.*"
        
        # Find dangerous function calls
        dangerous = [
            'strcpy', 'sprintf', 'gets', 'scanf', 'strcat',
            'memcpy', 'memmove', 'system', 'exec', 'eval',
            'unserialize', 'pickle.loads', 'innerHTML', 'eval'
        ]
        
        for df in dangerous:
            if df in code:
                patterns["dangerous_calls"].append(df)
        
        # Code structure markers (for AST similarity later)
        patterns["code_markers"] = [
            "has_loop" if any(k in code for k in ['for', 'while']) else None,
            "has_pointer" if '*' in code else None,
            "has_array_access" if '[' in code else None,
            "has_string_ops" if any(s in code for s in ['str', 'String', 'char']) else None
        ]
        patterns["code_markers"] = [m for m in patterns["code_markers"] if m]
        
        return patterns
    
    async def _search_codebase(
        self,
        project_path: str,
        patterns: Dict,
        vuln_type: str
    ) -> List[VariantCandidate]:
        """Search entire codebase for similar code patterns"""
        
        project_path = Path(project_path)
        candidates = []
        
        # Find all source files
        source_files = self._find_source_files(project_path)
        
        for file in source_files:
            try:
                content = file.read_text(errors='ignore')
            except:
                continue
            
            # Extract functions from file
            functions = self._extract_functions(content, str(file))
            
            for func in functions:
                # Calculate similarity
                score, reason = self._calculate_similarity(func, patterns)
                
                if score > 0.3:  # Threshold for potential variant
                    candidate = VariantCandidate(
                        fragment=func,
                        similarity_score=score,
                        similarity_reason=reason,
                        confidence=0.5  # Initial confidence, LLM will adjust
                    )
                    candidates.append(candidate)
        
        return candidates
    
    def _find_source_files(self, path: Path) -> List[Path]:
        """Find all source code files"""
        extensions = {'.c', '.cpp', '.cc', '.h', '.hpp', '.py', '.js', '.php', '.java', '.go', '.rs'}
        skip_dirs = {'node_modules', '.git', 'venv', '__pycache__', 'vendor', 'dist', 'build'}
        
        files = []
        for ext in extensions:
            for f in path.rglob(f'*{ext}'):
                if not any(skip in f.parts for skip in skip_dirs):
                    files.append(f)
        
        return files
    
    def _extract_functions(self, content: str, filepath: str) -> List[CodeFragment]:
        """
        Extract function definitions from source file.
        
        Simple regex-based extraction (not perfect, but fast).
        For production, use proper AST parsing.
        """
        functions = []
        
        # C/C++ style: return_type function_name(...) {
        c_pattern = r'(\w+[\s\*]+)?(\w+)\s*\([^)]*\)\s*\{'
        
        # Python style: def function_name(...):
        py_pattern = r'def\s+(\w+)\s*\([^)]*\):'
        
        # JavaScript style: function name(...) {
        js_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*\{'
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            # Try all patterns
            for pattern, group_idx in [
                (c_pattern, 2),
                (py_pattern, 1),
                (js_pattern, 1)
            ]:
                match = re.search(pattern, line)
                if match:
                    func_name = match.group(group_idx)
                    
                    # Extract function body (approximation)
                    start_line = i
                    end_line = min(i + 50, len(lines))  # Max 50 lines
                    
                    # Try to find closing brace
                    brace_count = 1
                    for j in range(i + 1, len(lines)):
                        if '{' in lines[j]:
                            brace_count += lines[j].count('{')
                        if '}' in lines[j]:
                            brace_count -= lines[j].count('}')
                        if brace_count == 0:
                            end_line = j + 1
                            break
                    
                    func_code = '\n'.join(lines[start_line:end_line])
                    
                    fragment = CodeFragment(
                        file=filepath,
                        function_name=func_name,
                        start_line=start_line + 1,
                        end_line=end_line + 1,
                        code=func_code,
                        signature=line.strip()
                    )
                    
                    functions.append(fragment)
                    break
        
        return functions
    
    def _calculate_similarity(
        self,
        fragment: CodeFragment,
        patterns: Dict
    ) -> Tuple[float, str]:
        """
        Calculate similarity score between fragment and vulnerability pattern.
        
        Returns (score, reason)
        """
        score = 0.0
        reasons = []
        
        # 1. Function name similarity
        if patterns.get("function_name"):
            orig_name = patterns["function_name"]
            
            # Exact match
            if fragment.function_name == orig_name:
                score += 0.9
                reasons.append("exact function name match")
            
            # Pattern match (e.g., parse_v1 vs parse_v2)
            elif patterns.get("function_pattern"):
                pattern = patterns["function_pattern"]
                if re.match(pattern, fragment.function_name, re.IGNORECASE):
                    score += 0.7
                    reasons.append(f"name pattern match: {pattern}")
            
            # Substring similarity
            else:
                ratio = SequenceMatcher(None, orig_name, fragment.function_name).ratio()
                if ratio > 0.6:
                    score += ratio * 0.5
                    reasons.append(f"name similarity: {ratio:.2f}")
        
        # 2. Dangerous function calls
        dangerous_in_frag = set()
        for df in patterns.get("dangerous_calls", []):
            if df in fragment.code:
                dangerous_in_frag.add(df)
        
        if dangerous_in_frag:
            score += min(len(dangerous_in_frag) * 0.2, 0.5)
            reasons.append(f"uses dangerous: {', '.join(dangerous_in_frag)}")
        
        # 3. Code structure similarity
        frag_markers = set()
        if any(k in fragment.code for k in ['for', 'while']):
            frag_markers.add("has_loop")
        if '*' in fragment.code:
            frag_markers.add("has_pointer")
        if '[' in fragment.code:
            frag_markers.add("has_array_access")
        if any(s in fragment.code for s in ['str', 'String', 'char']):
            frag_markers.add("has_string_ops")
        
        pattern_markers = set(patterns.get("code_markers", []))
        
        if pattern_markers:
            overlap = len(frag_markers & pattern_markers)
            if overlap > 0:
                struct_score = overlap / len(pattern_markers)
                score += struct_score * 0.3
                reasons.append(f"structure similarity: {struct_score:.2f}")
        
        return min(score, 1.0), "; ".join(reasons)
    
    async def _validate_candidates(
        self,
        candidates: List[VariantCandidate],
        original_vuln_code: str,
        vuln_type: str
    ) -> List[VariantCandidate]:
        """
        Use LLM to validate if candidates are actually vulnerable.
        
        Only validates high-similarity candidates to save API costs.
        """
        validated = []
        
        for candidate in candidates:
            if candidate.similarity_score < 0.5:
                continue  # Skip low similarity
            
            # Ask LLM
            prompt = f"""You are analyzing code for vulnerability variants.

ORIGINAL VULNERABLE CODE:
```
{original_vuln_code[:500]}
```

VULNERABILITY TYPE: {vuln_type}

CANDIDATE CODE (potentially similar vulnerability):
File: {candidate.fragment.file}:{candidate.fragment.start_line}
Function: {candidate.fragment.function_name}
```
{candidate.fragment.code[:500]}
```

QUESTION: Is this candidate code vulnerable to the same type of bug as the original?

Answer in JSON:
{{
  "is_vulnerable": true/false,
  "confidence": 0.0-1.0,
  "reason": "explanation of why vulnerable or not",
  "description": "brief description of the vulnerability if found"
}}
"""
            
            try:
                response = await self.llm.ask(
                    "You are a security expert analyzing code variants.",
                    prompt,
                    json_mode=True
                )
                
                import json
                result = json.loads(response) if isinstance(response, str) else response
                
                candidate.is_vulnerable = result.get("is_vulnerable", False)
                candidate.confidence = result.get("confidence", 0.5)
                candidate.description = result.get("description")
                
                if candidate.is_vulnerable:
                    validated.append(candidate)
            
            except Exception as e:
                print(f"[Variant Hunter] LLM validation error: {e}")
                continue
        
        return validated


# Convenience function
async def find_variants(
    project_path: str,
    vulnerable_code: str,
    vulnerable_location: str,
    vulnerability_type: str
) -> List[VariantCandidate]:
    """Find vulnerability variants in codebase"""
    hunter = VariantHunter()
    return await hunter.hunt_variants(
        project_path,
        vulnerable_code,
        vulnerable_location,
        vulnerability_type
    )
