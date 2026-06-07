#!/usr/bin/env python3
"""
Простой скрипт для парсинга GitHub Security Advisory Database
Показывает уязвимости, severity, affected packages
"""
import json
import os
from collections import Counter
from pathlib import Path

print("🔍 Парсим GitHub Security Advisories...\n")

# Путь к склонированному репозиторию
GHSA_PATH = Path.home() / "advisory-database"

if not GHSA_PATH.exists():
    print("❌ Папка advisory-database не найдена!")
    print("\nСначала склонируй:")
    print("  cd ~")
    print("  git clone https://github.com/github/advisory-database.git")
    print("\nЭто займёт ~2 минуты (100MB)")
    exit(1)

print(f"✅ Нашёл GitHub Advisory DB в {GHSA_PATH}\n")

advisories_dir = GHSA_PATH / "advisories" / "github-reviewed"

if not advisories_dir.exists():
    print(f"❌ Директория {advisories_dir} не найдена!")
    exit(1)

print("📊 Читаю JSON файлы...")

advisories = []
ecosystems = Counter()
severities = Counter()
cwe_ids = Counter()
years = Counter()

# Читаем все JSON файлы
json_files = list(advisories_dir.rglob("*.json"))
print(f"   Найдено {len(json_files):,} JSON файлов")
print()

# Парсим первые 10000 для статистики (чтобы быстро)
for json_file in json_files[:10000]:
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            advisories.append(data)
            
            # Статистика
            ecosystem = data.get('affected', [{}])[0].get('package', {}).get('ecosystem', 'unknown')
            ecosystems[ecosystem] += 1
            
            severity = data.get('database_specific', {}).get('severity', 'unknown')
            severities[severity] += 1
            
            # CWE
            for cwe in data.get('database_specific', {}).get('cwe_ids', []):
                cwe_ids[cwe] += 1
            
            # Год
            year = json_file.parent.parent.name
            years[year] += 1
    
    except Exception as e:
        continue

print(f"{'='*60}")
print("📈 СТАТИСТИКА GITHUB ADVISORIES")
print(f"{'='*60}\n")

print(f"🎯 Проанализировано: {len(advisories):,} advisory")
print()

print("🌍 ТОП-10 ЭКОСИСТЕМ:")
for ecosystem, count in ecosystems.most_common(10):
    print(f"  {ecosystem:20} {count:>6,} ({count/len(advisories)*100:.1f}%)")

print()
print("⚠️  SEVERITY DISTRIBUTION:")
for severity, count in severities.most_common():
    print(f"  {severity:15} {count:>6,} ({count/len(advisories)*100:.1f}%)")

print()
print("🐛 ТОП-15 CWE (типы уязвимостей):")
for cwe, count in cwe_ids.most_common(15):
    print(f"  {cwe:20} {count:>6,}")

print()
print("📅 ПО ГОДАМ:")
for year, count in sorted(years.items(), reverse=True)[:5]:
    print(f"  {year}: {count:>6,} advisories")

print()
print(f"{'='*60}")
print("💡 ПРИМЕРЫ УЯЗВИМОСТЕЙ")
print(f"{'='*60}\n")

for i, adv in enumerate(advisories[:5], 1):
    print(f"[{i}] {adv.get('summary', 'N/A')}")
    print(f"    ID: {adv.get('id', 'N/A')}")
    print(f"    Severity: {adv.get('database_specific', {}).get('severity', 'N/A')}")
    
    affected = adv.get('affected', [])
    if affected:
        pkg = affected[0].get('package', {})
        print(f"    Package: {pkg.get('ecosystem')}/{pkg.get('name')}")
    
    cves = adv.get('aliases', [])
    if cves:
        print(f"    CVE: {', '.join([c for c in cves if c.startswith('CVE')])}")
    
    print()

print(f"{'='*60}")
print("📄 ПРИМЕР JSON СТРУКТУРЫ")
print(f"{'='*60}\n")

if advisories:
    example = advisories[0]
    print(json.dumps(example, indent=2, ensure_ascii=False)[:1500])
    print("\n  ... (truncated)")

print()
print(f"{'='*60}")
print("✅ ГОТОВО!")
print(f"{'='*60}\n")

print("🎯 ЧТО ДАЛЬШЕ:")
print()
print("  1. Открой любой advisory JSON:")
print(f"     code ~/advisory-database/advisories/github-reviewed/2024/01/")
print()
print("  2. Найди конкретную уязвимость:")
print(f"     grep -r 'SQL injection' ~/advisory-database/advisories/ | head")
print()
print("  3. Посчитай все advisory:")
print(f"     find ~/advisory-database/advisories -name '*.json' | wc -l")
print()
print("  4. Экспортируй в CSV для обучения:")
print(f"     python3 export_ghsa_to_csv.py")
print()
