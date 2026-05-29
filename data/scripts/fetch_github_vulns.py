"""
GitHub Vulnerable Code Patterns Analyzer
Анализирует репозитории с известными уязвимостями для обучения модели
"""
import asyncio
import httpx
import json
from pathlib import Path

BASE = Path(__file__).parent.parent
RAW = BASE / "raw"
PROCESSED = BASE / "processed"

for d in [RAW, PROCESSED]:
    d.mkdir(exist_ok=True)


# Известные уязвимые проекты для анализа
VULNERABLE_REPOS = [
    # Web frameworks с CVE
    {"owner": "django", "repo": "django", "cves": ["CVE-2021-35042", "CVE-2022-34265"]},
    {"owner": "rails", "repo": "rails", "cves": ["CVE-2022-32224"]},
    {"owner": "expressjs", "repo": "express", "cves": ["CVE-2022-24999"]},
    
    # Intentionally vulnerable apps
    {"owner": "WebGoat", "repo": "WebGoat", "type": "training"},
    {"owner": "juice-shop", "repo": "juice-shop", "type": "training"},
    {"owner": "OWASP", "repo": "NodeGoat", "type": "training"},
    {"owner": "digininja", "repo": "DVWA", "type": "training"},
    
    # Real-world vulnerable code
    {"owner": "advisories", "repo": "GHSA", "type": "advisories"},
]


async def analyze_vulnerable_patterns(github_token: str = None) -> list:
    """Analyze code patterns from vulnerable repositories"""
    patterns = []
    
    headers = {}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    
    async with httpx.AsyncClient(timeout=60, headers=headers) as client:
        for repo_info in VULNERABLE_REPOS:
            owner = repo_info["owner"]
            repo = repo_info["repo"]
            
            print(f"  Analyzing {owner}/{repo}...")
            
            try:
                # Get repository info
                r = await client.get(f"https://api.github.com/repos/{owner}/{repo}")
                if r.status_code != 200:
                    continue
                
                repo_data = r.json()
                
                # Get security advisories if available
                r = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo}/security-advisories",
                    headers={"Accept": "application/vnd.github+json"}
                )
                
                advisories = []
                if r.status_code == 200:
                    advisories = r.json()
                
                # Get commits related to security fixes
                r = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo}/commits",
                    params={"per_page": 100}
                )
                
                if r.status_code == 200:
                    commits = r.json()
                    
                    for commit in commits:
                        msg = commit.get("commit", {}).get("message", "").lower()
                        
                        # Security-related commits
                        if any(kw in msg for kw in ["security", "cve", "vulnerability", "xss", "sqli", "injection", "bypass"]):
                            patterns.append({
                                "repo": f"{owner}/{repo}",
                                "commit_sha": commit["sha"],
                                "message": commit["commit"]["message"][:500],
                                "url": commit["html_url"],
                                "date": commit["commit"]["author"]["date"],
                                "type": "security_fix",
                                "source": "GitHub"
                            })
                
                # Add advisories
                for advisory in advisories:
                    patterns.append({
                        "repo": f"{owner}/{repo}",
                        "advisory_id": advisory.get("ghsa_id", ""),
                        "severity": advisory.get("severity", ""),
                        "summary": advisory.get("summary", "")[:500],
                        "description": advisory.get("description", "")[:1000],
                        "cve": advisory.get("cve_id", ""),
                        "type": "advisory",
                        "source": "GitHub"
                    })
                
                await asyncio.sleep(1)  # Rate limit
                
            except Exception as e:
                print(f"    Error: {e}")
    
    return patterns


def build_vulnerability_pattern_samples(patterns: list) -> list:
    """Convert patterns into training samples"""
    samples = []
    
    for pattern in patterns:
        if pattern["type"] == "security_fix":
            samples.append({
                "instruction": "Проанализируй этот security commit. Какая уязвимость была исправлена и как её можно было обнаружить?",
                "input": f"Repository: {pattern['repo']}\nCommit: {pattern['commit_sha']}\nMessage: {pattern['message']}",
                "output": f"""Анализ security commit:

Репозиторий: {pattern['repo']}
Commit: {pattern['url']}

Из commit message видно что исправлена уязвимость. 

Методология обнаружения подобных уязвимостей:
1. Code review — анализ изменений в коммите
2. Diff analysis — сравнение до/после патча
3. Pattern matching — поиск похожих паттернов в других местах
4. Regression testing — проверка что патч действительно закрывает уязвимость

Рекомендация: изучить diff коммита для понимания root cause."""
            })
        
        elif pattern["type"] == "advisory":
            samples.append({
                "instruction": f"Опиши уязвимость {pattern.get('cve', pattern.get('advisory_id'))} и как её обнаружить при пентесте.",
                "input": f"Advisory: {pattern.get('advisory_id')}\nCVE: {pattern.get('cve')}\nSeverity: {pattern.get('severity')}\nSummary: {pattern.get('summary')}",
                "output": f"""Уязвимость в {pattern['repo']}:

{pattern.get('description', pattern.get('summary'))}

Severity: {pattern.get('severity', 'N/A')}
CVE: {pattern.get('cve', 'N/A')}

Методология обнаружения:
1. Определить версию компонента
2. Проверить наличие уязвимости через PoC
3. Подтвердить exploitability
4. Задокументировать evidence

Рекомендация: обновить до пропатченной версии."""
            })
    
    return samples


async def main():
    print("Analyzing GitHub vulnerable code patterns...")
    
    # Try to get GitHub token from env
    import os
    github_token = os.getenv("GITHUB_TOKEN")
    
    patterns = await analyze_vulnerable_patterns(github_token)
    print(f"\nTotal patterns: {len(patterns)}")
    
    # Save raw
    with open(RAW / "github_vuln_patterns.json", "w") as f:
        json.dump(patterns, f, indent=2, ensure_ascii=False)
    
    # Build samples
    samples = build_vulnerability_pattern_samples(patterns)
    print(f"Training samples: {len(samples)}")
    
    # Save
    with open(PROCESSED / "github_vuln_samples.jsonl", "w") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    
    print(f"Saved to {PROCESSED}/github_vuln_samples.jsonl")


if __name__ == "__main__":
    asyncio.run(main())
