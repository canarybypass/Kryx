"""
fetch_nvd.py — CVE из NVD API v2 + PoC ссылки из GitHub Advisory
Фильтр: CVSS >= 7.0, последние 2 года
"""
import asyncio
import httpx
import json
import os
from pathlib import Path
from datetime import datetime, timedelta

BASE = Path(__file__).parent.parent
RAW = BASE / "raw"
RAW.mkdir(parents=True, exist_ok=True)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_API = "https://api.github.com/advisories"


async def fetch_nvd_cves(days_back: int = 730, min_cvss: float = 7.0) -> list:
    """Fetch CVEs from NVD API v2 with CVSS filter."""
    cves = []
    start_date = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00.000")
    end_date = datetime.utcnow().strftime("%Y-%m-%dT23:59:59.999")

    headers = {}
    if key := os.getenv("NVD_API_KEY"):
        headers["apiKey"] = key  # 50 req/30s with key vs 5 req/30s without

    params = {
        "pubStartDate": start_date,
        "pubEndDate": end_date,
        "cvssV3Severity": "HIGH",  # HIGH + CRITICAL = CVSS >= 7.0
        "resultsPerPage": 2000,
        "startIndex": 0,
    }

    async with httpx.AsyncClient(timeout=60, headers=headers) as client:
        while True:
            for attempt in range(3):
                try:
                    r = await client.get(NVD_API, params=params)
                    if r.status_code == 429:
                        await asyncio.sleep(35)
                        continue
                    r.raise_for_status()
                    break
                except Exception as e:
                    if attempt == 2:
                        raise
                    await asyncio.sleep(10)

            data = r.json()
            vulns = data.get("vulnerabilities", [])

            for item in vulns:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")

                # Description (English preferred)
                descs = cve.get("descriptions", [])
                desc = next((d["value"] for d in descs if d["lang"] == "en"), "")
                if not desc or len(desc) < 50:
                    continue

                # CVSS v3 score
                metrics = cve.get("metrics", {})
                cvss_score = None
                cvss_vector = ""
                attack_vector = ""
                for key in ("cvssMetricV31", "cvssMetricV30"):
                    if key in metrics and metrics[key]:
                        m = metrics[key][0]["cvssData"]
                        cvss_score = m.get("baseScore")
                        cvss_vector = m.get("vectorString", "")
                        attack_vector = m.get("attackVector", "")
                        break

                if cvss_score is None or cvss_score < min_cvss:
                    continue

                # CWE
                weaknesses = cve.get("weaknesses", [])
                cwes = []
                for w in weaknesses:
                    for d in w.get("description", []):
                        if d["value"].startswith("CWE-"):
                            cwes.append(d["value"])

                # References (PoC, exploit links)
                refs = cve.get("references", [])
                poc_links = []
                for ref in refs:
                    url = ref.get("url", "")
                    tags = ref.get("tags", [])
                    if any(t in tags for t in ("Exploit", "Patch", "Third Party Advisory")):
                        poc_links.append({"url": url, "tags": tags})

                cves.append({
                    "id": cve_id,
                    "description": desc,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "attack_vector": attack_vector,
                    "cwes": cwes,
                    "poc_links": poc_links[:5],
                    "published": cve.get("published", ""),
                    "source": "NVD",
                })

            total = data.get("totalResults", 0)
            fetched = params["startIndex"] + len(vulns)
            print(f"  NVD: {fetched}/{total} CVEs fetched...")

            if fetched >= total:
                break

            params["startIndex"] = fetched
            # NVD rate limit: 5 req/30s without key, 50 req/30s with key
            await asyncio.sleep(1 if os.getenv("NVD_API_KEY") else 7)

    # Also fetch CRITICAL severity
    params["cvssV3Severity"] = "CRITICAL"
    params["startIndex"] = 0

    async with httpx.AsyncClient(timeout=60, headers=headers) as client:
        while True:
            for attempt in range(3):
                try:
                    r = await client.get(NVD_API, params=params)
                    if r.status_code == 429:
                        await asyncio.sleep(35)
                        continue
                    r.raise_for_status()
                    break
                except Exception:
                    if attempt == 2:
                        break
                    await asyncio.sleep(10)

            data = r.json()
            vulns = data.get("vulnerabilities", [])

            for item in vulns:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")

                # Skip duplicates
                if any(c["id"] == cve_id for c in cves):
                    continue

                descs = cve.get("descriptions", [])
                desc = next((d["value"] for d in descs if d["lang"] == "en"), "")
                if not desc or len(desc) < 50:
                    continue

                metrics = cve.get("metrics", {})
                cvss_score = None
                cvss_vector = ""
                attack_vector = ""
                for key in ("cvssMetricV31", "cvssMetricV30"):
                    if key in metrics and metrics[key]:
                        m = metrics[key][0]["cvssData"]
                        cvss_score = m.get("baseScore")
                        cvss_vector = m.get("vectorString", "")
                        attack_vector = m.get("attackVector", "")
                        break

                weaknesses = cve.get("weaknesses", [])
                cwes = [
                    d["value"]
                    for w in weaknesses
                    for d in w.get("description", [])
                    if d["value"].startswith("CWE-")
                ]

                refs = cve.get("references", [])
                poc_links = [
                    {"url": ref["url"], "tags": ref.get("tags", [])}
                    for ref in refs
                    if any(t in ref.get("tags", []) for t in ("Exploit", "Patch", "Third Party Advisory"))
                ]

                cves.append({
                    "id": cve_id,
                    "description": desc,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "attack_vector": attack_vector,
                    "cwes": cwes,
                    "poc_links": poc_links[:5],
                    "published": cve.get("published", ""),
                    "source": "NVD",
                })

            total = data.get("totalResults", 0)
            fetched = params["startIndex"] + len(vulns)
            print(f"  NVD CRITICAL: {fetched}/{total} CVEs fetched...")

            if fetched >= total:
                break

            params["startIndex"] = fetched
            await asyncio.sleep(1 if os.getenv("NVD_API_KEY") else 7)

    return cves


async def fetch_github_advisories(limit: int = 2000) -> list:
    """Fetch GitHub Security Advisories with PoC references."""
    advisories = []
    headers = {"Accept": "application/vnd.github+json"}
    if token := os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=60, headers=headers) as client:
        page = 1
        while len(advisories) < limit:
            r = await client.get(
                GHSA_API,
                params={"per_page": 100, "page": page, "type": "reviewed"},
            )
            if r.status_code == 403:
                print("  GitHub rate limit hit, sleeping 60s...")
                await asyncio.sleep(60)
                continue
            if r.status_code != 200:
                break

            items = r.json()
            if not items:
                break

            for item in items:
                severity = item.get("severity", "")
                if severity not in ("high", "critical"):
                    continue

                # Extract PoC / patch references
                refs = item.get("references", []) or []
                poc_links = [r for r in refs if "github.com" in r or "exploit" in r.lower()]

                advisories.append({
                    "ghsa_id": item.get("ghsa_id", ""),
                    "cve_id": item.get("cve_id", ""),
                    "summary": item.get("summary", ""),
                    "description": (item.get("description") or "")[:1500],
                    "severity": severity,
                    "cvss_score": (item.get("cvss") or {}).get("score"),
                    "cwes": [c.get("cwe_id", "") for c in (item.get("cwes") or [])],
                    "poc_links": poc_links[:3],
                    "published_at": item.get("published_at", ""),
                    "source": "GitHub Advisory",
                })

            print(f"  GHSA: {len(advisories)} advisories fetched...")
            page += 1
            await asyncio.sleep(1)

    return advisories


def build_nvd_samples(cves: list, advisories: list) -> list:
    """Build high-quality training samples from CVE/advisory data."""
    samples = []

    for cve in cves:
        cve_id = cve["id"]
        desc = cve["description"]
        score = cve["cvss_score"]
        vector = cve["cvss_vector"]
        cwes = cve["cwes"]
        av = cve["attack_vector"]
        poc_links = cve["poc_links"]

        # Determine vuln class from CWE
        vuln_class = _cwe_to_class(cwes)
        severity_label = "CRITICAL" if score >= 9.0 else "HIGH"

        # Sample 1: pentest methodology for this CVE
        samples.append({
            "instruction": f"Ты проводишь пентест. Обнаружен компонент с {cve_id}. Опиши методологию подтверждения и эксплуатации.",
            "input": (
                f"CVE: {cve_id}\n"
                f"CVSS: {score} ({severity_label})\n"
                f"Vector: {vector}\n"
                f"Attack Vector: {av}\n"
                f"CWE: {', '.join(cwes) if cwes else 'N/A'}\n"
                f"Description: {desc[:600]}"
            ),
            "output": _generate_pentest_methodology(cve_id, desc, score, av, vuln_class, poc_links),
            "source": "nvd",
            "cve_id": cve_id,
            "cvss": score,
        })

        # Sample 2: detection and triage
        if score >= 9.0:
            samples.append({
                "instruction": f"Как быстро определить наличие {cve_id} на целевом хосте? Дай конкретные команды.",
                "input": (
                    f"CVE: {cve_id}\n"
                    f"CVSS: {score}\n"
                    f"Description: {desc[:400]}"
                ),
                "output": _generate_detection_commands(cve_id, desc, av, vuln_class),
                "source": "nvd",
                "cve_id": cve_id,
                "cvss": score,
            })

    for adv in advisories:
        if not adv.get("description") and not adv.get("summary"):
            continue

        text = adv.get("description") or adv.get("summary", "")
        cve_ref = adv.get("cve_id") or adv.get("ghsa_id")
        score = adv.get("cvss_score")
        cwes = adv.get("cwes", [])
        vuln_class = _cwe_to_class(cwes)

        samples.append({
            "instruction": f"Проанализируй advisory {cve_ref}. Какой класс уязвимости, как эксплуатируется, как обнаружить?",
            "input": (
                f"Advisory: {cve_ref}\n"
                f"Severity: {adv['severity'].upper()}\n"
                f"CVSS: {score or 'N/A'}\n"
                f"CWE: {', '.join(cwes) if cwes else 'N/A'}\n"
                f"Summary: {adv['summary']}\n"
                f"Description: {text[:800]}"
            ),
            "output": _generate_advisory_analysis(adv, vuln_class),
            "source": "github_advisory",
            "cve_id": cve_ref,
            "cvss": score,
        })

    return samples


def _cwe_to_class(cwes: list) -> str:
    mapping = {
        "CWE-89": "SQL Injection",
        "CWE-79": "Cross-Site Scripting (XSS)",
        "CWE-78": "OS Command Injection",
        "CWE-22": "Path Traversal",
        "CWE-94": "Code Injection",
        "CWE-287": "Authentication Bypass",
        "CWE-306": "Missing Authentication",
        "CWE-502": "Deserialization",
        "CWE-611": "XXE Injection",
        "CWE-918": "SSRF",
        "CWE-434": "Unrestricted File Upload",
        "CWE-798": "Hardcoded Credentials",
        "CWE-200": "Information Disclosure",
        "CWE-416": "Use After Free",
        "CWE-125": "Out-of-bounds Read",
        "CWE-787": "Out-of-bounds Write",
        "CWE-190": "Integer Overflow",
        "CWE-476": "NULL Pointer Dereference",
    }
    for cwe in cwes:
        if cwe in mapping:
            return mapping[cwe]
    return "Unknown Vulnerability Class"


def _generate_pentest_methodology(
    cve_id: str, desc: str, score: float, av: str, vuln_class: str, poc_links: list
) -> str:
    network_step = (
        "1. Разведка: определить версию компонента через nmap -sV, HTTP headers, whatweb"
        if av in ("NETWORK", "ADJACENT")
        else "1. Разведка: получить локальный доступ к системе, определить версию компонента"
    )

    poc_note = ""
    if poc_links:
        urls = [p["url"] for p in poc_links[:2]]
        poc_note = f"\nИзвестные PoC/патчи:\n" + "\n".join(f"  - {u}" for u in urls)

    return f"""Класс уязвимости: {vuln_class}
CVSS: {score} | Attack Vector: {av}

Методология подтверждения {cve_id}:

{network_step}
2. Сопоставить версию с диапазоном уязвимых версий из NVD
3. Поиск готового шаблона: nuclei -t cves/{cve_id.lower().replace('-', '-')}.yaml -u <target>
4. Если шаблона нет — изучить патч (diff между уязвимой и пропатченной версией)
5. Написать минимальный PoC на основе описания уязвимости
6. Выполнить PoC в контролируемой среде, зафиксировать evidence
7. Задокументировать: скриншот ответа, payload, версию компонента

Критерий подтверждения: получен ответ, однозначно доказывающий уязвимость (RCE output, SQL error, file content).
Не считается подтверждённым: только совпадение версии без проверки exploitability.{poc_note}

Рекомендация по исправлению: обновить компонент до версии, в которой устранена {cve_id}."""


def _generate_detection_commands(cve_id: str, desc: str, av: str, vuln_class: str) -> str:
    nuclei_cmd = f"nuclei -t cves/ -id {cve_id.lower()} -u https://target.com"
    nmap_cmd = "nmap -sV --script vulners -p 80,443,8080,8443 target.com"

    return f"""Быстрое обнаружение {cve_id} ({vuln_class}):

# Шаг 1: Проверка через nuclei (если есть шаблон)
{nuclei_cmd}

# Шаг 2: Определение версии компонента
{nmap_cmd}

# Шаг 3: HTTP fingerprinting
curl -sI https://target.com | grep -i "server\\|x-powered-by\\|x-generator"
whatweb https://target.com

# Шаг 4: Поиск PoC на GitHub
# Ищи: site:github.com {cve_id} PoC exploit

Интерпретация результатов:
- Если nuclei вернул [critical] — уязвимость подтверждена автоматически
- Если только версия совпадает — требуется ручная верификация PoC
- Attack vector: {av} — {'доступно удалённо без аутентификации' if av == 'NETWORK' else 'требует локального доступа'}"""


def _generate_advisory_analysis(adv: dict, vuln_class: str) -> str:
    cve_ref = adv.get("cve_id") or adv.get("ghsa_id")
    text = adv.get("description") or adv.get("summary", "")

    return f"""Класс уязвимости: {vuln_class}
Severity: {adv['severity'].upper()} | CVSS: {adv.get('cvss_score', 'N/A')}
CWE: {', '.join(adv.get('cwes', [])) or 'N/A'}

Анализ {cve_ref}:
{text[:700]}

Вектор эксплуатации:
- Определить затронутый компонент и версию
- Проверить наличие патча в репозитории проекта
- Воспроизвести по описанию или diff патча

Обнаружение при пентесте:
1. Fingerprint технологии (версия, конфигурация)
2. Сопоставить с диапазоном уязвимых версий
3. Запустить nuclei / написать кастомный check
4. Подтвердить через PoC с реальным evidence

Рекомендация: применить патч или обновить до исправленной версии."""


async def main():
    print("=" * 50)
    print("fetch_nvd.py — CVE + GitHub Advisory")
    print("=" * 50)

    print("\n[1/2] Fetching NVD CVEs (CVSS >= 7.0, last 2 years)...")
    cves = await fetch_nvd_cves(days_back=730, min_cvss=7.0)
    print(f"  ✓ {len(cves)} CVEs")

    print("\n[2/2] Fetching GitHub Security Advisories...")
    advisories = await fetch_github_advisories(limit=2000)
    print(f"  ✓ {len(advisories)} advisories")

    # Save raw
    with open(RAW / "nvd_cves.json", "w") as f:
        json.dump(cves, f, ensure_ascii=False, indent=2)

    with open(RAW / "github_advisories.json", "w") as f:
        json.dump(advisories, f, ensure_ascii=False, indent=2)

    # Build samples
    samples = build_nvd_samples(cves, advisories)
    print(f"\n✓ Built {len(samples)} training samples")

    out = BASE / "processed"
    out.mkdir(exist_ok=True)
    with open(out / "nvd_samples.jsonl", "w") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    print(f"Saved → data/processed/nvd_samples.jsonl")
    print(f"\nStats:")
    print(f"  CVEs: {len(cves)}")
    print(f"  Advisories: {len(advisories)}")
    print(f"  Training samples: {len(samples)}")


if __name__ == "__main__":
    asyncio.run(main())
