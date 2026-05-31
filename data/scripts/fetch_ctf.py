"""
fetch_ctf.py — CTF writeups из CTFtime API + GitHub репозитории
Собирает реальные writeups с решениями задач
"""
import asyncio
import httpx
import json
import re
import os
from pathlib import Path

BASE = Path(__file__).parent.parent
RAW = BASE / "raw"
RAW.mkdir(parents=True, exist_ok=True)

CTFTIME_API = "https://ctftime.org/api/v1"
GITHUB_API = "https://api.github.com"

# Категории CTF задач которые нас интересуют
INTERESTING_CATEGORIES = {
    "web", "pwn", "crypto", "forensics", "reverse",
    "misc", "network", "binary", "exploitation", "sqli",
}

# Известные репозитории с writeups
WRITEUP_REPOS = [
    "CTFd/CTFd",
    "w181496/Web-CTF-Cheatsheet",
    "swisskyrepo/PayloadsAllTheThings",
    "carlospolop/hacktricks",
    "sixstars/ctf-writeups",
    "p4-team/ctf",
    "ctfs/ctfs",
    "bl4de/ctf",
    "smokeleeteveryday/CTF_WRITEUPS",
]


async def fetch_ctftime_writeups(limit: int = 1000) -> list:
    """Fetch writeup links from CTFtime API."""
    writeups = []

    async with httpx.AsyncClient(timeout=30, headers={"User-Agent": "Mozilla/5.0"}) as client:
        page = 1
        while len(writeups) < limit:
            try:
                r = await client.get(
                    f"{CTFTIME_API}/writeups/",
                    params={"limit": 100, "offset": (page - 1) * 100},
                )
                if r.status_code != 200:
                    break

                items = r.json()
                if not items:
                    break

                for item in items:
                    task = item.get("task", {})
                    category = task.get("category_name", "").lower()

                    # Filter by interesting categories
                    if not any(cat in category for cat in INTERESTING_CATEGORIES):
                        continue

                    writeups.append({
                        "id": item.get("id"),
                        "title": task.get("title", ""),
                        "category": category,
                        "event": item.get("event", {}).get("title", ""),
                        "url": item.get("url", ""),
                        "date": item.get("date", ""),
                        "source": "CTFtime",
                    })

                print(f"  CTFtime: {len(writeups)} writeups...")
                page += 1
                await asyncio.sleep(1)

            except Exception as e:
                print(f"  CTFtime error: {e}")
                break

    return writeups


async def fetch_writeup_content(url: str, client: httpx.AsyncClient) -> str | None:
    """Fetch and extract text content from a writeup URL."""
    if not url or not url.startswith("http"):
        return None

    try:
        r = await client.get(url, timeout=20, follow_redirects=True)
        if r.status_code != 200:
            return None

        text = r.text

        # Extract meaningful text (strip HTML tags)
        # Remove scripts and styles
        text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)
        # Strip remaining HTML tags
        text = re.sub(r"<[^>]+>", " ", text)
        # Normalize whitespace
        text = re.sub(r"\s+", " ", text).strip()

        if len(text) < 200:
            return None

        return text[:5000]

    except Exception:
        return None


async def fetch_github_writeup_repos(limit_per_repo: int = 50) -> list:
    """Fetch writeup markdown files from known GitHub repos."""
    writeups = []
    headers = {"Accept": "application/vnd.github+json"}
    if token := os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        # Search GitHub for CTF writeup repos
        search_queries = [
            "ctf writeup web exploitation",
            "ctf writeup pwn binary",
            "ctf writeup sql injection",
        ]

        for query in search_queries:
            try:
                r = await client.get(
                    f"{GITHUB_API}/search/repositories",
                    params={
                        "q": f"{query} in:description,name",
                        "sort": "stars",
                        "per_page": 10,
                    },
                )
                if r.status_code != 200:
                    continue

                repos = r.json().get("items", [])
                for repo in repos[:5]:
                    full_name = repo["full_name"]
                    # Fetch markdown files from repo
                    md_files = await _fetch_repo_markdowns(client, full_name, limit_per_repo)
                    writeups.extend(md_files)
                    await asyncio.sleep(1)

            except Exception as e:
                print(f"  GitHub search error: {e}")

            await asyncio.sleep(2)

    return writeups


async def _fetch_repo_markdowns(
    client: httpx.AsyncClient, full_name: str, limit: int
) -> list:
    """Fetch markdown writeup files from a GitHub repo."""
    results = []

    try:
        # Search for markdown files in repo
        r = await client.get(
            f"{GITHUB_API}/search/code",
            params={
                "q": f"writeup OR solution OR exploit repo:{full_name} extension:md",
                "per_page": min(limit, 30),
            },
        )
        if r.status_code != 200:
            return results

        items = r.json().get("items", [])
        for item in items:
            raw_url = item.get("html_url", "").replace(
                "github.com", "raw.githubusercontent.com"
            ).replace("/blob/", "/")

            try:
                r2 = await client.get(raw_url, timeout=15)
                if r2.status_code == 200 and len(r2.text) > 300:
                    results.append({
                        "title": item.get("name", ""),
                        "repo": full_name,
                        "path": item.get("path", ""),
                        "content": r2.text[:5000],
                        "url": item.get("html_url", ""),
                        "source": "GitHub",
                    })
            except Exception:
                pass

            await asyncio.sleep(0.5)

    except Exception as e:
        print(f"  Repo {full_name} error: {e}")

    return results


def build_ctf_samples(ctftime_writeups: list, github_writeups: list) -> list:
    """Build training samples from CTF writeups."""
    samples = []

    # CTFtime writeups (metadata only — content requires fetching each URL)
    for w in ctftime_writeups:
        if not w.get("title"):
            continue

        category = w.get("category", "misc")
        samples.append({
            "instruction": f"Это CTF задача категории {category.upper()}. Опиши методологию решения подобных задач.",
            "input": (
                f"CTF: {w.get('event', 'Unknown CTF')}\n"
                f"Task: {w['title']}\n"
                f"Category: {category}\n"
                f"Writeup URL: {w.get('url', 'N/A')}"
            ),
            "output": _generate_ctf_methodology(w),
            "source": "ctftime",
            "category": category,
        })

    # GitHub writeups (have actual content)
    for w in github_writeups:
        content = w.get("content", "")
        if not content or len(content) < 300:
            continue

        # Detect category from content
        category = _detect_category(content)

        samples.append({
            "instruction": "Проанализируй этот CTF writeup. Какая уязвимость/техника использована и как к ней пришли?",
            "input": (
                f"Repo: {w.get('repo', '')}\n"
                f"File: {w.get('path', '')}\n\n"
                f"Content:\n{content[:2000]}"
            ),
            "output": _analyze_writeup(w, category),
            "source": "github_ctf",
            "category": category,
        })

        # If content has exploit code — add code analysis sample
        if _has_code(content):
            samples.append({
                "instruction": "В этом CTF writeup есть код решения. Объясни как он работает и какую уязвимость эксплуатирует.",
                "input": f"Writeup excerpt:\n{content[:3000]}",
                "output": _analyze_ctf_code(w, content, category),
                "source": "github_ctf",
                "category": category,
            })

    return samples


def _detect_category(content: str) -> str:
    content_lower = content.lower()
    if any(kw in content_lower for kw in ("sql injection", "xss", "ssrf", "lfi", "rfi", "php", "flask", "django")):
        return "web"
    if any(kw in content_lower for kw in ("buffer overflow", "rop chain", "shellcode", "gdb", "pwntools", "libc")):
        return "pwn"
    if any(kw in content_lower for kw in ("rsa", "aes", "cipher", "decrypt", "modular", "elliptic")):
        return "crypto"
    if any(kw in content_lower for kw in ("wireshark", "pcap", "strings", "binwalk", "steganography")):
        return "forensics"
    if any(kw in content_lower for kw in ("ida", "ghidra", "disassembly", "decompile", "reverse")):
        return "reverse"
    return "misc"


def _has_code(content: str) -> bool:
    return "```" in content or "import " in content or "def " in content


def _generate_ctf_methodology(w: dict) -> str:
    category = w.get("category", "misc")

    methodologies = {
        "web": """Методология решения Web CTF задач:

1. Разведка: изучить функционал приложения, найти все endpoints
2. Анализ исходного кода (если доступен): искать уязвимые паттерны
3. Тестирование входных точек:
   - SQL injection: ' OR 1=1--, UNION SELECT, blind SQLi
   - XSS: <script>alert(1)</script>, DOM-based XSS
   - LFI/RFI: ../../../etc/passwd, php://filter
   - SSRF: внутренние адреса, cloud metadata
4. Анализ cookies и JWT токенов
5. Проверка HTTP headers и методов
6. Поиск скрытых endpoints (gobuster, ffuf)
7. Получить флаг: обычно в /flag, /etc/flag, переменной окружения FLAG""",

        "pwn": """Методология решения Pwn/Binary Exploitation задач:

1. Анализ бинаря: file, checksec (NX, PIE, RELRO, canary)
2. Статический анализ: Ghidra/IDA — найти уязвимую функцию
3. Динамический анализ: GDB + pwndbg/peda
4. Определить тип уязвимости:
   - Buffer overflow: переполнение стека/кучи
   - Format string: %x%x%x, %n для записи
   - Use-after-free: heap exploitation
5. Построить exploit:
   - Найти offset до return address
   - ROP chain если NX включён
   - Leak libc адреса если PIE включён
6. Получить shell: system("/bin/sh") или one_gadget""",

        "crypto": """Методология решения Crypto CTF задач:

1. Определить алгоритм шифрования
2. Найти слабость:
   - RSA: малая экспонента, общий модуль, Wiener attack
   - AES: ECB mode (penguin attack), padding oracle
   - Custom cipher: frequency analysis, known plaintext
3. Инструменты: SageMath, pycryptodome, RsaCtfTool
4. Математический анализ параметров
5. Написать скрипт дешифровки""",

        "forensics": """Методология решения Forensics CTF задач:

1. Определить тип файла: file, xxd (magic bytes)
2. Извлечь данные: strings, binwalk, foremost
3. Стеганография: steghide, zsteg, stegsolve
4. Анализ трафика: Wireshark, tshark
5. Анализ дампа памяти: Volatility
6. Метаданные: exiftool
7. Поиск флага в извлечённых данных""",
    }

    return methodologies.get(category, f"""Методология решения CTF задачи ({category}):

1. Изучить условие задачи и предоставленные файлы
2. Определить тип уязвимости или техники
3. Применить соответствующие инструменты
4. Итеративно тестировать гипотезы
5. Получить флаг в формате CTF{{...}}

Задача: {w.get('title', 'N/A')}
CTF: {w.get('event', 'N/A')}""")


def _analyze_writeup(w: dict, category: str) -> str:
    content = w.get("content", "")

    # Extract key lines (headers, code blocks indicators)
    lines = content.split("\n")
    key_lines = [l.strip() for l in lines if l.strip().startswith("#") or "flag" in l.lower()]
    key_summary = "\n".join(key_lines[:10]) if key_lines else "Смотри полный контент"

    return f"""Анализ CTF writeup:

Категория: {category.upper()}
Репозиторий: {w.get('repo', 'N/A')}
Файл: {w.get('path', 'N/A')}

Ключевые моменты:
{key_summary}

Техника/уязвимость:
Определяется из контента writeup. Категория {category} предполагает:
{_category_techniques(category)}

Применение в реальном пентесте:
Техники из CTF задач напрямую применимы к реальным целям.
Разница: в реальности нет гарантированного флага, нужно искать реальные данные/доступ."""


def _analyze_ctf_code(w: dict, content: str, category: str) -> str:
    # Extract code blocks
    code_blocks = re.findall(r"```(?:\w+)?\n(.*?)```", content, re.DOTALL)
    code_sample = code_blocks[0][:1500] if code_blocks else content[:1000]

    return f"""Анализ кода решения CTF задачи ({category.upper()}):

```
{code_sample}
```

Что делает этот код:
- Реализует эксплойт для уязвимости категории {category}
- Автоматизирует процесс получения флага
- Использует специфичные для категории техники

Ключевые паттерны:
{_category_code_patterns(category)}

Адаптация для пентеста:
Логику эксплойта можно адаптировать для реальных целей,
заменив CTF-специфичные параметры на реальные endpoint'ы."""


def _category_techniques(category: str) -> str:
    techniques = {
        "web": "SQL injection, XSS, SSRF, LFI, IDOR, JWT manipulation, deserialization",
        "pwn": "Buffer overflow, ROP chains, heap exploitation, format string bugs",
        "crypto": "RSA attacks, padding oracle, frequency analysis, hash collisions",
        "forensics": "Steganography, traffic analysis, memory forensics, file carving",
        "reverse": "Static/dynamic analysis, anti-debug bypass, algorithm reconstruction",
        "misc": "Разнообразные техники в зависимости от задачи",
    }
    return techniques.get(category, "Специфичные для задачи техники")


def _category_code_patterns(category: str) -> str:
    patterns = {
        "web": "requests/httpx для HTTP, BeautifulSoup для парсинга, re для regex",
        "pwn": "pwntools (p64, u64, remote, process), ROP gadgets, shellcraft",
        "crypto": "pycryptodome, SageMath, gmpy2 для математики",
        "forensics": "scapy для pcap, PIL для изображений, struct для бинарных данных",
        "reverse": "capstone для дизассемблирования, angr для symbolic execution",
    }
    return patterns.get(category, "Стандартные Python библиотеки")


async def main():
    print("=" * 50)
    print("fetch_ctf.py — CTF writeups")
    print("=" * 50)

    print("\n[1/2] Fetching CTFtime writeups...")
    ctftime = await fetch_ctftime_writeups(limit=1000)
    print(f"  ✓ {len(ctftime)} writeups from CTFtime")

    print("\n[2/2] Fetching GitHub CTF writeup repos...")
    github = await fetch_github_writeup_repos(limit_per_repo=30)
    print(f"  ✓ {len(github)} writeups from GitHub")

    # Save raw
    with open(RAW / "ctf_ctftime.json", "w") as f:
        json.dump(ctftime, f, ensure_ascii=False, indent=2)

    with open(RAW / "ctf_github.json", "w") as f:
        json.dump(github, f, ensure_ascii=False, indent=2)

    # Build samples
    samples = build_ctf_samples(ctftime, github)
    print(f"\n✓ Built {len(samples)} training samples")

    out = BASE / "processed"
    out.mkdir(exist_ok=True)
    with open(out / "ctf_samples.jsonl", "w") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    print(f"Saved → data/processed/ctf_samples.jsonl")

    # Category distribution
    cats = {}
    for s in samples:
        c = s.get("category", "misc")
        cats[c] = cats.get(c, 0) + 1
    print(f"\nCategory distribution: {cats}")


if __name__ == "__main__":
    asyncio.run(main())
