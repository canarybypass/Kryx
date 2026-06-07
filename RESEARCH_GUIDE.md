# Research Guide — Сбор данных для обучения модели

## Шаг 1: Склонируй датасеты

### Exploit-DB (~300MB, 5 минут)
```bash
cd ~
git clone https://gitlab.com/exploit-database/exploitdb.git
```

### GitHub Advisory Database (~100MB, 2 минуты)
```bash
cd ~
git clone https://github.com/github/advisory-database.git
```

---

## Шаг 2: Запусти мои скрипты анализа

### Exploit-DB
```bash
cd /home/offsys/hexor
python3 research_exploitdb.py
```

**Что покажет:**
- Сколько всего эксплойтов (50,000+)
- Сколько с CVE ID
- Топ-10 платформ (Windows, Linux, PHP, etc)
- Топ-10 типов уязвимостей (RCE, LPE, DoS, SQLi)
- Примеры кода эксплойтов

### GitHub Advisory
```bash
cd /home/offsys/hexor
python3 research_ghsa.py
```

**Что покажет:**
- Количество advisory
- Распределение по severity (critical/high/medium/low)
- Топ-15 CWE типов
- Экосистемы (npm, PyPI, Maven, Go, etc)
- Примеры JSON структуры

---

## Шаг 3: Изучи структуру данных

### Exploit-DB структура

**CSV файл:** `~/exploitdb/files_exploits.csv`

Колонки:
- `id` — уникальный ID
- `file` — путь к файлу с кодом
- `description` — описание уязвимости
- `date` — дата публикации
- `author` — автор эксплойта
- `type` — тип (remote, local, webapps, dos, etc)
- `platform` — платформа (windows, linux, php, hardware, etc)
- `codes` — CVE ID (если есть)

**Пример строки:**
```csv
50808,exploits/linux/local/50808.c,"Linux Kernel 5.8 - 'fs/jfs/jfs_dmap.c' Local Privilege Escalation",2022-11-09,Jann Horn,local,linux,"CVE-2022-3524"
```

**Код эксплойта:** `~/exploitdb/exploits/linux/local/50808.c`

### GitHub Advisory структура

**JSON файл:** `~/advisory-database/advisories/github-reviewed/2024/01/GHSA-xxxx-xxxx-xxxx.json`

Ключевые поля:
```json
{
  "id": "GHSA-xxxx-xxxx-xxxx",
  "summary": "SQL Injection in some-package",
  "details": "Подробное описание уязвимости...",
  "severity": "HIGH",
  "affected": [
    {
      "package": {
        "ecosystem": "npm",
        "name": "some-package"
      },
      "ranges": [
        {
          "type": "SEMVER",
          "events": [
            {"introduced": "0"},
            {"fixed": "1.2.3"}
          ]
        }
      ]
    }
  ],
  "database_specific": {
    "severity": "HIGH",
    "cwe_ids": ["CWE-89"]
  },
  "aliases": ["CVE-2024-12345"],
  "references": [
    {
      "type": "WEB",
      "url": "https://github.com/user/repo/security/advisories/GHSA-xxxx"
    }
  ]
}
```

---

## Шаг 4: Примеры команд для изучения

### Найти все RCE эксплойты
```bash
grep -i 'remote code execution' ~/exploitdb/files_exploits.csv | wc -l
```

### Найти все buffer overflow
```bash
grep -i 'buffer overflow' ~/exploitdb/files_exploits.csv | head -10
```

### Посмотреть код эксплойта
```bash
cat ~/exploitdb/exploits/linux/local/50808.c
```

### Найти все Python эксплойты
```bash
find ~/exploitdb/exploits -name "*.py" | head -20
```

### Найти SQL injection в GitHub Advisory
```bash
grep -r '"CWE-89"' ~/advisory-database/advisories/ | wc -l
```

### Посмотреть advisory про npm пакеты
```bash
find ~/advisory-database/advisories -name "*.json" -exec grep -l '"ecosystem": "npm"' {} \; | head -10
```

---

## Шаг 5: Что ты ищешь (для отчёта мне)

Посчитай и запиши:

### Exploit-DB:
- [ ] Всего эксплойтов: _______
- [ ] С CVE ID: _______
- [ ] RCE exploits: _______
- [ ] Privilege Escalation: _______
- [ ] Buffer overflow: _______
- [ ] Файлов на Python: _______
- [ ] Файлов на C/C++: _______

### GitHub Advisory:
- [ ] Всего advisory: _______
- [ ] Critical severity: _______
- [ ] SQL injection (CWE-89): _______
- [ ] XSS (CWE-79): _______
- [ ] Memory corruption (CWE-119, CWE-120, CWE-416): _______
- [ ] npm экосистема: _______
- [ ] PyPI экосистема: _______

---

## Шаг 6: Открой примеры в VS Code

```bash
# Открой папку Exploit-DB
code ~/exploitdb/exploits

# Открой папку GitHub Advisory
code ~/advisory-database/advisories
```

Полистай файлы — посмотри как выглядят:
1. Реальные эксплойты (C, Python, PHP)
2. Описания уязвимостей
3. CVE references
4. Patched versions

---

## Шаг 7: Экспорт данных (позже)

Когда разберёшься — мы напишем скрипт который:
1. Парсит все эти данные
2. Чистит и форматирует
3. Создаёт CSV/JSON для обучения модели

**Формат для обучения:**
```json
{
  "vulnerability_description": "Buffer overflow in strcpy function...",
  "vulnerable_code": "char buf[10]; strcpy(buf, user_input);",
  "exploit_code": "payload = b'A' * 100 + ...",
  "cve_id": "CVE-2024-1234",
  "severity": "critical",
  "type": "memory_corruption",
  "platform": "linux"
}
```

---

## Полезные ссылки

- **Exploit-DB**: https://www.exploit-db.com/
- **GitHub Advisory**: https://github.com/advisories
- **NVD (CVE Database)**: https://nvd.nist.gov/
- **CWE (Weakness Types)**: https://cwe.mitre.org/
- **CAPEC (Attack Patterns)**: https://capec.mitre.org/

---

## Если застрял

Пиши мне:
- "Не понимаю структуру CSV"
- "Как найти конкретный тип уязвимости"
- "Как открыть и посмотреть код"
- "Что значит CWE-89"

Я объясню!
