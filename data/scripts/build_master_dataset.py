"""
Master Dataset Builder
Собирает все источники и строит финальный training dataset
"""
import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime

# Add scripts to path
sys.path.insert(0, str(Path(__file__).parent))

from fetch_mitre import fetch_mitre, build_mitre_samples
from fetch_hackerone import fetch_hackerone_reports
from fetch_arxiv import fetch_arxiv_papers

BASE = Path(__file__).parent.parent
RAW = BASE / "raw"
PROCESSED = BASE / "processed"

for d in [RAW, PROCESSED]:
    d.mkdir(parents=True, exist_ok=True)


class MasterDatasetBuilder:
    """Orchestrates all data collection and dataset building"""
    
    def __init__(self):
        self.stats = {
            "sources": {},
            "total_samples": 0,
            "started_at": datetime.now().isoformat()
        }
    
    async def collect_all_sources(self):
        """Collect from all sources in parallel"""
        print("=" * 60)
        print("HEXOR MASTER DATASET BUILDER")
        print("=" * 60)
        
        tasks = []
        
        # CVE (already collected, load from raw)
        print("\n[1/6] Loading CVE data...")
        cve_path = RAW / "cve_raw.json"
        if cve_path.exists():
            with open(cve_path) as f:
                cves = json.load(f)
            print(f"  ✓ {len(cves)} CVEs loaded")
            self.stats["sources"]["cve"] = len(cves)
        else:
            print("  ⚠ No CVE data, run build_dataset.py first")
            cves = []
        
        # ExploitDB (already collected)
        print("\n[2/6] Loading ExploitDB data...")
        edb_path = RAW / "exploitdb_raw.json"
        if edb_path.exists():
            with open(edb_path) as f:
                exploits = json.load(f)
            print(f"  ✓ {len(exploits)} exploits loaded")
            self.stats["sources"]["exploitdb"] = len(exploits)
        else:
            print("  ⚠ No ExploitDB data")
            exploits = []
        
        # MITRE ATT&CK
        print("\n[3/6] Fetching MITRE ATT&CK...")
        mitre_techniques = await fetch_mitre()
        mitre_samples = build_mitre_samples(mitre_techniques)
        print(f"  ✓ {len(mitre_samples)} MITRE samples")
        self.stats["sources"]["mitre"] = len(mitre_samples)
        
        # HackerOne
        print("\n[4/6] Fetching HackerOne reports...")
        h1_reports = await fetch_hackerone_reports(500)
        print(f"  ✓ {len(h1_reports)} HackerOne reports")
        self.stats["sources"]["hackerone"] = len(h1_reports)
        
        # arXiv
        print("\n[5/6] Fetching arXiv papers...")
        papers = await fetch_arxiv_papers(300)
        print(f"  ✓ {len(papers)} arXiv papers")
        self.stats["sources"]["arxiv"] = len(papers)
        
        # GitHub (from analyze_github.py if exists)
        print("\n[6/6] Loading GitHub analysis...")
        gh_path = PROCESSED / "github_repo_samples.jsonl"
        gh_vuln_path = PROCESSED / "github_vuln_samples.jsonl"
        github_samples = []
        
        if gh_path.exists():
            with open(gh_path) as f:
                for line in f:
                    github_samples.append(json.loads(line))
            print(f"  ✓ {len(github_samples)} GitHub repo samples")
        
        if gh_vuln_path.exists():
            with open(gh_vuln_path) as f:
                for line in f:
                    github_samples.append(json.loads(line))
            print(f"  ✓ {len(github_samples)} GitHub vuln samples (total)")
        
        if not github_samples:
            print("  ⚠ No GitHub data, run analyze_github.py")
        
        self.stats["sources"]["github"] = len(github_samples)
        
        # Writeups
        print("\n[7/7] Loading writeups...")
        writeups_path = RAW / "writeups_raw.json"
        if writeups_path.exists():
            with open(writeups_path) as f:
                writeups = json.load(f)
            print(f"  ✓ {len(writeups)} writeups")
            self.stats["sources"]["writeups"] = len(writeups)
        else:
            print("  ⚠ No writeups, run fetch_writeups.py")
            writeups = []
        
        return {
            "cves": cves,
            "exploits": exploits,
            "mitre": mitre_samples,
            "hackerone": h1_reports,
            "arxiv": papers,
            "github": github_samples,
            "writeups": writeups
        }
    
    def build_training_samples(self, data: dict) -> list:
        """Convert all raw data into training format"""
        samples = []
        
        # CVE samples
        for cve in data["cves"]:
            if cve.get("description"):
                samples.append({
                    "instruction": "Проанализируй эту уязвимость. Опиши класс, вектор атаки, impact, и методологию обнаружения при пентесте.",
                    "input": f"CVE: {cve.get('id')}\nSeverity: {cve.get('severity')}\nCVSS: {cve.get('cvss_score')}\nDescription: {cve.get('description')}",
                    "output": self._generate_cve_analysis(cve),
                    "source": "cve"
                })
        
        # ExploitDB samples
        for exploit in data["exploits"]:
            if exploit.get("description"):
                samples.append({
                    "instruction": "Опиши пошаговый процесс эксплуатации этой уязвимости.",
                    "input": f"Exploit: {exploit.get('description')}\nType: {exploit.get('type')}",
                    "output": self._generate_exploit_steps(exploit),
                    "source": "exploitdb"
                })
        
        # MITRE samples (already formatted)
        samples.extend(data["mitre"])
        
        # HackerOne samples
        for report in data["hackerone"]:
            if report.get("summary"):
                samples.append({
                    "instruction": f"Как найти уязвимость типа {report.get('weakness')} при пентесте?",
                    "input": f"Vulnerability: {report.get('weakness')}\nSeverity: {report.get('severity')}\nContext: {report.get('title')}",
                    "output": self._generate_h1_methodology(report),
                    "source": "hackerone"
                })
        
        # arXiv samples
        for paper in data["arxiv"]:
            samples.append({
                "instruction": "Какие техники и подходы описаны в этой security research paper?",
                "input": f"Title: {paper.get('title')}\nSummary: {paper.get('summary')[:500]}",
                "output": self._generate_paper_insights(paper),
                "source": "arxiv"
            })
        
        # GitHub samples (already formatted)
        for sample in data["github"]:
            sample["source"] = "github"
            samples.append(sample)
        
        # Writeups
        for writeup in data["writeups"]:
            if writeup.get("title"):
                samples.append({
                    "instruction": "Какие техники и уязвимости описаны в этом bug bounty writeup?",
                    "input": f"Title: {writeup.get('title')}\nSummary: {writeup.get('summary', writeup.get('description', ''))[:500]}",
                    "output": self._generate_writeup_analysis(writeup),
                    "source": "writeups"
                })
        
        return samples
    
    def _generate_cve_analysis(self, cve: dict) -> str:
        return f"""Класс уязвимости: {cve.get('cwe', 'Определяется по описанию')}
Severity: {cve.get('severity', 'MEDIUM')} (CVSS {cve.get('cvss_score', 'N/A')})
Вектор атаки: {cve.get('attack_vector', 'NETWORK')}

Описание:
{cve.get('description', '')[:400]}

Методология обнаружения при пентесте:
1. Определить компонент/сервис из описания CVE
2. Проверить версию через баннеры (nmap -sV, whatweb, HTTP headers)
3. Если версия уязвима — подтвердить через nuclei с шаблоном {cve.get('id', '')}
4. При отсутствии готового шаблона — написать кастомный PoC
5. Задокументировать evidence (скриншоты, логи, вывод инструментов)

Рекомендация: обновить компонент до пропатченной версии."""
    
    def _generate_exploit_steps(self, exploit: dict) -> str:
        return f"""Пошаговая эксплуатация:
1. Подготовка: определить целевую систему и версию ПО
2. Доставка payload: использовать вектор {exploit.get('type', 'remote/local')}
3. Триггер уязвимости: выполнить эксплойт согласно описанию
4. Верификация: подтвердить получение привилегий/доступа
5. Post-exploitation: закрепиться, собрать данные

Инструменты: Metasploit, custom script
Описание: {exploit.get('description', '')[:300]}"""
    
    def _generate_h1_methodology(self, report: dict) -> str:
        return f"""Методология обнаружения {report.get('weakness', 'уязвимости')}:

1. Изучить функционал приложения, связанный с этим типом уязвимости
2. Определить точки входа (API endpoints, параметры, формы)
3. Проверить обработку пользовательского ввода — отправить тестовые payload'ы
4. Проанализировать ответы сервера на признаки уязвимости
5. При обнаружении — написать PoC и зафиксировать evidence

Severity: {report.get('severity', 'N/A')}
Bounty: ${report.get('bounty', 'N/A')}

Рекомендация: исправить логику обработки в соответствии с best practices."""
    
    def _generate_paper_insights(self, paper: dict) -> str:
        return f"""Ключевые техники из research paper:

{paper.get('summary', '')[:600]}

Применение в пентесте:
- Изучить описанные техники и инструменты
- Адаптировать подходы для реальных целей
- Использовать как референс для новых методологий

Авторы: {', '.join(paper.get('authors', [])[:3])}
Категории: {', '.join(paper.get('categories', []))}"""
    
    def _generate_writeup_analysis(self, writeup: dict) -> str:
        return f"""Анализ bug bounty writeup:

{writeup.get('summary', writeup.get('description', ''))[:500]}

Ключевые моменты:
- Изучить методологию автора
- Понять как была обнаружена уязвимость
- Применить похожие техники на других целях
- Обратить внимание на bypass техники

Source: {writeup.get('source', 'Unknown')}
Link: {writeup.get('link', 'N/A')}"""
    
    def save_dataset(self, samples: list):
        """Save in JSONL format"""
        ts = datetime.now().strftime("%Y%m%d_%H%M")
        
        # Full dataset
        full_path = PROCESSED / f"hexor_dataset_{ts}.jsonl"
        with open(full_path, "w") as f:
            for s in samples:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")
        
        # Train/val split (80/20)
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
        self.stats["total_samples"] = len(samples)
        self.stats["train_samples"] = len(train)
        self.stats["val_samples"] = len(val)
        self.stats["completed_at"] = datetime.now().isoformat()
        
        with open(PROCESSED / f"stats_{ts}.json", "w") as f:
            json.dump(self.stats, f, indent=2)
        
        print(f"\n{'='*60}")
        print("DATASET BUILT SUCCESSFULLY")
        print(f"{'='*60}")
        print(f"Total samples: {len(samples)}")
        print(f"Train: {len(train)}")
        print(f"Val: {len(val)}")
        print(f"\nSaved to: {PROCESSED}/")
        print(f"  - train.jsonl")
        print(f"  - val.jsonl")
        print(f"  - hexor_dataset_{ts}.jsonl")
        
        print(f"\nSource distribution:")
        for source, count in self.stats["sources"].items():
            print(f"  {source}: {count}")


async def main():
    builder = MasterDatasetBuilder()
    
    # Collect all data
    data = await builder.collect_all_sources()
    
    # Build training samples
    print("\n" + "="*60)
    print("BUILDING TRAINING SAMPLES")
    print("="*60)
    samples = builder.build_training_samples(data)
    
    # Save
    builder.save_dataset(samples)


if __name__ == "__main__":
    asyncio.run(main())
