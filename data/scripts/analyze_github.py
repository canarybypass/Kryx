"""
GitHub Repository Analyzer for Kryx Dataset

Analyzes popular open-source projects to teach the model:
1. How real codebases are structured
2. Where vulnerabilities typically hide
3. How to approach pentesting specific project types
"""
import json
import asyncio
import httpx
from pathlib import Path

BASE = Path(__file__).parent.parent
GITHUB_DIR = BASE / "github_repos"
RAW = BASE / "raw"


# Popular open-source projects by category — teaches model real-world architecture
TARGET_REPOS = {
    "web_frameworks": [
        {"owner": "django", "repo": "django", "type": "Python web framework"},
        {"owner": "flask", "repo": "flask", "type": "Python micro-framework"},
        {"owner": "expressjs", "repo": "express", "type": "Node.js web framework"},
        {"owner": "spring-projects", "repo": "spring-framework", "type": "Java enterprise framework"},
        {"owner": "laravel", "repo": "framework", "type": "PHP web framework"},
        {"owner": "ruby", "repo": "ruby-on-rails", "type": "Ruby web framework"},
    ],
    "databases": [
        {"owner": "postgres", "repo": "postgres", "type": "SQL database"},
        {"owner": "redis", "repo": "redis", "type": "In-memory key-value store"},
        {"owner": "mongodb", "repo": "mongo", "type": "NoSQL document database"},
        {"owner": "mysql", "repo": "mysql-server", "type": "SQL database"},
    ],
    "infrastructure": [
        {"owner": "kubernetes", "repo": "kubernetes", "type": "Container orchestration"},
        {"owner": "nginx", "repo": "nginx", "type": "Web server / reverse proxy"},
        {"owner": "docker", "repo": "docker-ce", "type": "Container runtime"},
        {"owner": "ansible", "repo": "ansible", "type": "Configuration management"},
    ],
    "security_tools": [
        {"owner": "nmap", "repo": "nmap", "type": "Network scanner"},
        {"owner": "sqlmapproject", "repo": "sqlmap", "type": "SQL injection tool"},
        {"owner": "hashcat", "repo": "hashcat", "type": "Password cracking"},
    ],
}


async def fetch_repo_info(client: httpx.AsyncClient, owner: str, repo: str) -> dict | None:
    """Fetch repository metadata from GitHub API."""
    try:
        r = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers={"Accept": "application/vnd.github.v3+json"},
        )
        if r.status_code == 200:
            return r.json()
        print(f"  {owner}/{repo}: HTTP {r.status_code}")
    except Exception as e:
        print(f"  {owner}/{repo}: {e}")
    return None


async def fetch_repo_tree(client: httpx.AsyncClient, owner: str, repo: str) -> list | None:
    """Fetch repository file tree."""
    try:
        r = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/git/trees/main?recursive=1",
            headers={"Accept": "application/vnd.github.v3+json"},
        )
        if r.status_code == 200:
            return r.json().get("tree", [])
        # Try 'master' branch
        r = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/git/trees/master?recursive=1",
            headers={"Accept": "application/vnd.github.v3+json"},
        )
        if r.status_code == 200:
            return r.json().get("tree", [])
    except Exception:
        pass
    return None


def analyze_structure(owner: str, repo: str, repo_type: str, info: dict, tree: list) -> dict:
    """Analyze repository structure and identify security-relevant patterns."""
    if not tree:
        return {}

    # Count files by extension
    extensions = {}
    dirs = set()
    config_files = []
    security_files = []

    for item in tree:
        path = item.get("path", "")
        if "." in path:
            ext = path.rsplit(".", 1)[1].lower()
            extensions[ext] = extensions.get(ext, 0) + 1

        # Get top-level dirs
        parts = path.split("/")
        if len(parts) >= 1:
            dirs.add(parts[0])

        # Security-relevant files
        if any(s in path.lower() for s in [
            "auth", "login", "password", "token", "session", "csrf",
            "sanitize", "validate", "escape", "crypto", "encrypt",
            "permission", "acl", "rbac", "oauth", "jwt", "sso",
        ]):
            security_files.append(path)

        # Config files
        if any(c in path.lower() for c in [
            ".env", "config", "settings", "dockerfile", "docker-compose",
            "requirements.txt", "package.json", "pom.xml", "build.gradle",
            "makefile", "cmakelists", ".gitignore", "nginx.conf",
        ]):
            config_files.append(path)

    return {
        "name": f"{owner}/{repo}",
        "type": repo_type,
        "description": (info.get("description") or "")[:300] if info else "",
        "stars": info.get("stargazers_count", 0) if info else 0,
        "language": info.get("language", "") if info else "",
        "top_dirs": sorted(dirs)[:15],
        "extensions": dict(sorted(extensions.items(), key=lambda x: -x[1])[:10]),
        "config_files": config_files[:20],
        "security_files": security_files[:20],
        "total_files": len(tree),
    }


def build_repo_samples(repos_data: list[dict]) -> list[dict]:
    """Build training samples teaching how to pentest specific project types."""
    samples = []

    for repo in repos_data:
        if not repo.get("type"):
            continue

        repo_type = repo["type"]
        name = repo["name"]
        desc = repo.get("description", "")
        language = repo.get("language", "")
        dirs = repo.get("top_dirs", [])
        security_files = repo.get("security_files", [])
        config_files = repo.get("config_files", [])

        # Sample 1: Architecture overview
        samples.append({
            "instruction": f"Проанализируй архитектуру проекта {name} ({repo_type}). Где искать уязвимости?",
            "input": (
                f"Project: {name}\n"
                f"Type: {repo_type}\n"
                f"Language: {language}\n"
                f"Structure: {', '.join(dirs[:10])}\n"
                f"Description: {desc}"
            ),
            "output": _generate_arch_analysis(name, repo_type, language, dirs, security_files, config_files),
        })

        # Sample 2: Where vulns hide in this type
        samples.append({
            "instruction": f"Ты пентестишь {repo_type} написанный на {language}. Какие классы уязвимостей наиболее вероятны и где их искать?",
            "input": f"Target type: {repo_type} ({language})\nProject example: {name}",
            "output": _generate_vuln_guide(repo_type, language, dirs),
        })

    return samples


def _generate_arch_analysis(name: str, repo_type: str, language: str,
                            dirs: list, security_files: list, config_files: list) -> str:
    return (
        f"Архитектура {name} ({repo_type}):\n\n"
        f"Язык: {language}\n"
        f"Структура проекта: {', '.join(dirs[:10])}\n\n"
        f"Точки входа для пентестера:\n"
        f"1. Конфигурационные файлы: {', '.join(config_files[:5]) or 'не найдены'}\n"
        f"   - Проверить на hardcoded secrets, default credentials, debug mode\n"
        f"2. Модули безопасности: {', '.join(security_files[:5]) or 'не найдены'}\n"
        f"   - Проверить логику аутентификации, авторизации, валидации\n"
        f"3. API endpoints — искать в routes/, controllers/, views/\n"
        f"4. ORM/DB queries — искать в models/, repositories/\n\n"
        f"Приоритетные классы уязвимостей для {repo_type} на {language}:\n"
        f"- Injection (SQL, command, template) — проверять все user inputs\n"
        f"- Broken Access Control — проверять permission checks\n"
        f"- Security Misconfiguration — проверять default settings\n"
        f"- Cryptographic Failures — проверять хранение паролей и токенов"
    )


def _generate_vuln_guide(repo_type: str, language: str, dirs: list) -> str:
    guides = {
        "Python web framework": (
            "Ключевые уязвимости Python web framework:\n\n"
            "1. SSTI (Server-Side Template Injection):\n"
            "   - Искать в шаблонах: render_template_string(user_input)\n"
            "   - Jinja2: {{config}}, {{7*7}}\n\n"
            "2. Mass Assignment:\n"
            "   - Flask: request.form.to_dict() без whitelist\n"
            "   - Django: ModelForm без fields или с __all__\n\n"
            "3. Pickle Deserialization:\n"
            "   - pickle.loads(user_input) → RCE\n"
            "   - Искать в cookies, API, file uploads\n\n"
            "4. Debug Mode:\n"
            "   - Flask debug=True → Werkzeug console → RCE\n"
            "   - Django DEBUG=True → verbose errors → info leak\n\n"
            "5. ORM Injection:\n"
            "   - Django: .extra(), .raw() без параметризации\n"
            "   - SQLAlchemy: text() с format string"
        ),
        "Node.js web framework": (
            "Ключевые уязвимости Node.js web framework:\n\n"
            "1. Prototype Pollution:\n"
            "   - merge()/extend() без sanitization\n"
            "   - JSON.parse + __proto__ → RCE/LFI\n\n"
            "2. RCE через eval/exec:\n"
            "   - eval(user_input), child_process.exec(user_input)\n"
            "   - Искать в routes, middleware\n\n"
            "3. NoSQL Injection (MongoDB):\n"
            "   - {$ne: null}, {$gt: ''}\n"
            "   - Bypass auth: {\"$gt\": \"\"}\n\n"
            "4. JWT Issues:\n"
            "   - jsonwebtoken без algorithm проверки\n"
            "   - 'none' algorithm, weak secret\n\n"
            "5. SSRF через HTTP клиенты:\n"
            "   - axios.get(user_url), request(user_url)"
        ),
        "Java enterprise framework": (
            "Ключевые уязвимости Java enterprise framework:\n\n"
            "1. Insecure Deserialization:\n"
            "   - ObjectInputStream без фильтрации → RCE\n"
            "   - Jackson/Fastjson polymorphic deserialization\n\n"
            "2. Spring4Shell / Spring Actuator:\n"
            "   - /actuator/env, /actuator/heapdump\n"
            "   - CVE-2022-22965, CVE-2022-22947\n\n"
            "3. Expression Language Injection:\n"
            "   - ${7*7} в JSP/JSF\n"
            "   - SpEL injection: T(java.lang.Runtime).getRuntime().exec()\n\n"
            "4. XXE:\n"
            "   - XML parsers без защиты → file read, SSRF, DoS\n"
            "   - DocumentBuilderFactory, SAXParser\n\n"
            "5. JNDI Injection:\n"
            "   - ldap://, rmi:// в JNDI lookup → RCE"
        ),
        "PHP web framework": (
            "Ключевые уязвимости PHP web framework:\n\n"
            "1. Laravel Deserialization:\n"
            "   - unserialize() через cookie/session\n"
            "   - Gadget chains в illuminate/*\n\n"
            "2. Type Juggling:\n"
            "   - \"0e12345\" == \"0e67890\" → true\n"
            "   - Magic hashes в password comparison\n\n"
            "3. File Upload:\n"
            "   - .php, .phtml, .phar, .php5 → RCE\n"
            "   - MIME type bypass, double extension\n\n"
            "4. SQL Injection:\n"
            "   - DB::raw(), ->whereRaw()\n"
            "   - Order by/Group by без параметризации\n\n"
            "5. Environment exposure:\n"
            "   - .env через misconfigured nginx\n"
            "   - php artisan debug mode"
        ),
        "SQL database": (
            "Ключевые уязвимости SQL database:\n\n"
            "1. Default Credentials:\n"
            "   - postgres:postgres, root:root, sa:\n"
            "   - Проверить через nmap + metasploit\n\n"
            "2. Network Exposure:\n"
            "   - Порт 3306/5432/1433 открыт наружу\n"
            "   - Нет firewall rules\n\n"
            "3. Weak Authentication:\n"
            "   - trust auth в pg_hba.conf\n"
            "   - skip-grant-tables в MySQL\n"
            "   - Empty password для root\n\n"
            "4. SQL Injection через приложения:\n"
            "   - UNION-based, error-based, blind, time-based\n"
            "   - sqlmap автоматически\n\n"
            "5. Privilege Escalation:\n"
            "   - UDF (User Defined Functions) → RCE\n"
            "   - LOAD DATA LOCAL INFILE → file read\n"
            "   - COPY ... PROGRAM (PostgreSQL) → RCE"
        ),
    }

    # Find best matching guide
    for key, guide in guides.items():
        if key.lower() in repo_type.lower() or key.lower() in language.lower():
            return guide

    # Generic guide
    return (
        f"Ключевые уязвимости {repo_type} на {language}:\n\n"
        f"1. Проверить все точки входа (API, формы, импорт)\n"
        f"2. Тестировать injection через все параметры\n"
        f"3. Проверить аутентификацию и авторизацию\n"
        f"4. Искать hardcoded secrets в конфигах\n"
        f"5. Проверить зависимости на известные CVE\n"
        f"6. Тестировать обработку ошибок — не раскрывают ли инфу"
    )


async def main():
    GITHUB_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("GITHUB REPO ANALYZER FOR HEXOR DATASET")
    print("=" * 60)

    all_repos = []

    async with httpx.AsyncClient(timeout=30) as client:
        for category, repos in TARGET_REPOS.items():
            print(f"\n[Category: {category}]")
            for repo_info in repos:
                owner = repo_info["owner"]
                repo = repo_info["repo"]
                repo_type = repo_info["type"]

                print(f"  Fetching {owner}/{repo}...")
                info = await fetch_repo_info(client, owner, repo)
                tree = await fetch_repo_tree(client, owner, repo)

                if info:
                    analysis = analyze_structure(owner, repo, repo_type, info, tree or [])
                    if analysis:
                        all_repos.append(analysis)
                        print(f"    -> {analysis['total_files']} files, {analysis['stars']} stars")

                await asyncio.sleep(0.5)  # Rate limit

    # Save raw data
    with open(RAW / "github_repos_raw.json", "w") as f:
        json.dump(all_repos, f, indent=2)

    # Build training samples
    samples = build_repo_samples(all_repos)
    print(f"\nBuilt {len(samples)} repository analysis samples")

    # Save
    out = BASE / "processed"
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "github_repo_samples.jsonl", "w") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    print(f"Saved to {out}/github_repo_samples.jsonl")
    return samples


if __name__ == "__main__":
    asyncio.run(main())