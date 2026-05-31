"""
Hexor Code Auditor — статический анализ исходного кода через LLM
Mythos-style: taint analysis + variant analysis по всей кодовой базе
"""
import asyncio
import json
import os
import re
import zipfile
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from utils.llm import get_llm
from core.agents.prompts import CODE_TAINT_PROMPT, CODE_VARIANT_PROMPT, CODE_SUMMARY_PROMPT

# Языки и расширения которые анализируем
SUPPORTED_EXTENSIONS = {
    ".py", ".php", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".rb", ".go", ".cs", ".cpp", ".c",
}

# Файлы которые пропускаем
SKIP_PATTERNS = {
    "node_modules", ".git", "__pycache__", "vendor",
    "dist", "build", ".venv", "venv", "migrations",
    "test", "tests", "spec", ".min.js",
}

# Максимальный размер файла для анализа (байт)
MAX_FILE_SIZE = 100_000  # 100KB

# Максимум файлов за один аудит
MAX_FILES = 200

# Chunk размер для больших файлов (строк)
CHUNK_LINES = 300


@dataclass
class AuditResult:
    source: str  # repo URL или путь
    language_stats: dict = field(default_factory=dict)
    files_analyzed: int = 0
    findings: list = field(default_factory=list)
    variants: list = field(default_factory=list)
    report: str = ""
    stats: dict = field(default_factory=dict)


class CodeAuditor:
    """
    Агент аудита исходного кода.
    Принимает: GitHub URL, zip/tar архив, или локальный путь.
    Выполняет: taint analysis + variant analysis + итоговый отчёт.
    """

    def __init__(self, progress_cb=None):
        self.progress_cb = progress_cb
        self.llm = get_llm()

    async def run(self, source: str, github_token: str | None = None) -> dict:
        await self._emit("status", "loading")

        # Load codebase
        code_dir = await self._load_source(source, github_token)
        if not code_dir:
            return {"error": f"Could not load source: {source}"}

        result = AuditResult(source=source)

        # Collect files
        files = self._collect_files(code_dir)
        result.language_stats = self._language_stats(files)
        result.files_analyzed = len(files)

        await self._emit("status", "analyzing")
        await self._emit("stats", {
            "files": len(files),
            "languages": result.language_stats,
        })

        # Stage 1: Taint analysis — parallel across files
        await self._emit("status", "taint_analysis")
        findings = await self._run_taint_analysis(files)
        result.findings = findings

        await self._emit("findings", findings)

        # Stage 2: Variant analysis — find similar patterns
        if findings:
            await self._emit("status", "variant_analysis")
            variants = await self._run_variant_analysis(findings, files)
            result.variants = variants
            await self._emit("variants", variants)

        # Stage 3: Generate report
        await self._emit("status", "reporting")
        result.report = await self._generate_report(result)

        result.stats = {
            "files_analyzed": result.files_analyzed,
            "total_findings": len(result.findings),
            "by_severity": self._count_severity(result.findings),
            "by_type": self._count_type(result.findings),
            "variants_found": len(result.variants),
        }

        await self._emit("status", "done")
        await self._emit("report", result.report)

        return self._to_dict(result)

    # ── Source loading ──────────────────────────────────────

    async def _load_source(self, source: str, github_token: str | None) -> Path | None:
        tmp = Path(tempfile.mkdtemp(prefix="hexor-audit-"))

        # GitHub URL
        if "github.com" in source:
            return await self._clone_github(source, tmp, github_token)

        # Local path
        p = Path(source)
        if p.is_dir():
            return p
        if p.is_file() and p.suffix in (".zip", ".tar", ".gz", ".tgz"):
            return self._extract_archive(p, tmp)

        return None

    async def _clone_github(
        self, url: str, dest: Path, token: str | None
    ) -> Path | None:
        import httpx

        # Parse owner/repo from URL
        match = re.search(r"github\.com/([^/]+)/([^/\s]+?)(?:\.git)?$", url)
        if not match:
            return None

        owner, repo = match.group(1), match.group(2)

        # Download as zip (no git needed)
        zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            async with httpx.AsyncClient(timeout=60, headers=headers, follow_redirects=True) as client:
                r = await client.get(zip_url)
                if r.status_code != 200:
                    return None

                zip_path = dest / "repo.zip"
                zip_path.write_bytes(r.content)
                return self._extract_archive(zip_path, dest / "repo")
        except Exception as e:
            await self._emit("error", f"GitHub clone failed: {e}")
            return None

    def _extract_archive(self, archive: Path, dest: Path) -> Path | None:
        dest.mkdir(parents=True, exist_ok=True)
        try:
            if archive.suffix == ".zip" or str(archive).endswith(".zip"):
                with zipfile.ZipFile(archive) as z:
                    z.extractall(dest)
            elif archive.suffix in (".tar", ".gz", ".tgz") or str(archive).endswith((".tar.gz", ".tgz")):
                with tarfile.open(archive) as t:
                    t.extractall(dest)
            else:
                return None

            # If extracted into a single subdirectory, return that
            children = list(dest.iterdir())
            if len(children) == 1 and children[0].is_dir():
                return children[0]
            return dest
        except Exception:
            return None

    # ── File collection ─────────────────────────────────────

    def _collect_files(self, root: Path) -> list[dict]:
        files = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in SUPPORTED_EXTENSIONS:
                continue
            if any(skip in str(path) for skip in SKIP_PATTERNS):
                continue
            if path.stat().st_size > MAX_FILE_SIZE:
                continue
            if len(files) >= MAX_FILES:
                break

            try:
                content = path.read_text(errors="replace")
                files.append({
                    "path": str(path.relative_to(root)),
                    "abs_path": str(path),
                    "language": self._detect_language(path.suffix),
                    "content": content,
                    "lines": len(content.splitlines()),
                    "size": path.stat().st_size,
                })
            except Exception:
                continue

        # Prioritize files likely to have vulns
        files.sort(key=lambda f: self._vuln_priority(f), reverse=True)
        return files

    def _detect_language(self, suffix: str) -> str:
        return {
            ".py": "python", ".php": "php", ".js": "javascript",
            ".ts": "typescript", ".jsx": "javascript", ".tsx": "typescript",
            ".java": "java", ".rb": "ruby", ".go": "go",
            ".cs": "csharp", ".cpp": "cpp", ".c": "c",
        }.get(suffix, "unknown")

    def _vuln_priority(self, f: dict) -> int:
        """Score files by likelihood of containing vulnerabilities."""
        score = 0
        path_lower = f["path"].lower()
        content_lower = f["content"].lower()

        # High-value paths
        for kw in ("route", "view", "controller", "api", "auth", "login", "upload", "admin"):
            if kw in path_lower:
                score += 3

        # Dangerous patterns in content
        for pattern in (
            "execute(", "cursor.execute", "query(", "raw(",  # SQL
            "os.system", "subprocess", "shell_exec", "exec(",  # RCE
            "pickle.loads", "unserialize", "yaml.load",  # Deserialize
            "render_template_string", "eval(",  # SSTI/eval
            "request.args", "request.form", "$_GET", "$_POST",  # Sources
            "open(", "include(", "require(",  # File ops
        ):
            if pattern in content_lower:
                score += 2

        return score

    def _language_stats(self, files: list) -> dict:
        stats = {}
        for f in files:
            lang = f["language"]
            stats[lang] = stats.get(lang, 0) + 1
        return stats

    # ── Taint analysis ──────────────────────────────────────

    async def _run_taint_analysis(self, files: list) -> list:
        """Run taint analysis on all files in parallel (batched)."""
        # Only analyze files with vuln priority > 0
        candidates = [f for f in files if self._vuln_priority(f) > 0]
        if not candidates:
            candidates = files[:50]  # fallback: analyze first 50

        # Batch: max 20 concurrent LLM calls
        sem = asyncio.Semaphore(20)
        tasks = [self._analyze_file(f, sem) for f in candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings = []
        for r in results:
            if isinstance(r, Exception) or not r:
                continue
            all_findings.extend(r)

        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_findings.sort(key=lambda x: sev_order.get(x.get("severity", "low"), 3))

        return all_findings

    async def _analyze_file(self, file: dict, sem: asyncio.Semaphore) -> list:
        async with sem:
            content = file["content"]
            path = file["path"]
            lang = file["language"]

            # Split large files into chunks
            lines = content.splitlines()
            chunks = [
                lines[i: i + CHUNK_LINES]
                for i in range(0, len(lines), CHUNK_LINES)
            ]

            findings = []
            for chunk_idx, chunk in enumerate(chunks):
                offset = chunk_idx * CHUNK_LINES
                chunk_text = "\n".join(
                    f"{offset + i + 1:4d} | {line}"
                    for i, line in enumerate(chunk)
                )

                prompt = f"""File: {path}
Language: {lang}
Lines: {offset + 1}–{offset + len(chunk)}

```{lang}
{chunk_text}
```

Perform taint analysis. Find all paths from user-controlled sources to dangerous sinks."""

                try:
                    response = await self.llm.ask(CODE_TAINT_PROMPT, prompt)
                    parsed = _parse_json(response)
                    if parsed and parsed.get("findings"):
                        for f in parsed["findings"]:
                            f["file"] = path
                            # Adjust line numbers for chunk offset
                            if "line_start" in f:
                                f["line_start"] = f["line_start"]
                            findings.extend(parsed["findings"])
                        # Emit progress
                        if self.progress_cb and findings:
                            await self._emit("file_analyzed", {
                                "file": path,
                                "findings_count": len(parsed["findings"]),
                            })
                except Exception:
                    pass

            return findings

    # ── Variant analysis ────────────────────────────────────

    async def _run_variant_analysis(self, findings: list, files: list) -> list:
        """Find variants of discovered vulnerability patterns."""
        if not findings:
            return []

        # Group findings by type
        by_type: dict[str, list] = {}
        for f in findings:
            t = f.get("type", "unknown")
            by_type.setdefault(t, []).append(f)

        # Build codebase summary for variant search
        codebase_summary = self._build_codebase_summary(files)

        variants = []
        sem = asyncio.Semaphore(5)

        async def find_variants(vuln_type: str, type_findings: list):
            async with sem:
                # Take the most severe finding as the pattern
                pattern_finding = type_findings[0]

                prompt = f"""Original vulnerability pattern found:
Type: {vuln_type}
File: {pattern_finding.get('file')}
Code: {pattern_finding.get('code_snippet', '')}
Taint path: {pattern_finding.get('taint_path', '')}

Codebase structure and code snippets:
{codebase_summary}

Find all variants of this vulnerability pattern in the codebase."""

                try:
                    response = await self.llm.ask(CODE_VARIANT_PROMPT, prompt)
                    parsed = _parse_json(response)
                    if parsed and parsed.get("variants_found"):
                        return parsed["variants_found"]
                except Exception:
                    pass
                return []

        tasks = [find_variants(t, f) for t, f in by_type.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if not isinstance(r, Exception) and r:
                variants.extend(r)

        return variants

    def _build_codebase_summary(self, files: list) -> str:
        """Build a compact summary of the codebase for variant analysis."""
        lines = []
        for f in files[:50]:  # limit context size
            content_preview = f["content"][:500].replace("\n", " ")
            lines.append(f"### {f['path']} ({f['language']}, {f['lines']} lines)\n{content_preview}\n")
        return "\n".join(lines)[:8000]

    # ── Report generation ───────────────────────────────────

    async def _generate_report(self, result: AuditResult) -> str:
        data = {
            "source": result.source,
            "files_analyzed": result.files_analyzed,
            "language_stats": result.language_stats,
            "findings": result.findings,
            "variants": result.variants,
            "stats": {
                "by_severity": self._count_severity(result.findings),
                "by_type": self._count_type(result.findings),
            },
        }

        prompt = f"""Code audit results:

{json.dumps(data, indent=2, ensure_ascii=False)[:6000]}

Write the full professional code audit report in Russian markdown."""

        return await self.llm.ask(CODE_SUMMARY_PROMPT, prompt, json_mode=False)

    # ── Helpers ─────────────────────────────────────────────

    def _count_severity(self, findings: list) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "low")
            if sev in counts:
                counts[sev] += 1
        return counts

    def _count_type(self, findings: list) -> dict:
        counts: dict = {}
        for f in findings:
            t = f.get("type", "unknown")
            counts[t] = counts.get(t, 0) + 1
        return counts

    def _to_dict(self, result: AuditResult) -> dict:
        return {
            "source": result.source,
            "files_analyzed": result.files_analyzed,
            "language_stats": result.language_stats,
            "findings": result.findings,
            "variants": result.variants,
            "report": result.report,
            "stats": result.stats,
        }

    async def _emit(self, event: str, data):
        if self.progress_cb:
            await self.progress_cb({"event": event, "data": data})


def _parse_json(text: str) -> dict | None:
    try:
        return json.loads(text)
    except Exception:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except Exception:
                pass
    return None
