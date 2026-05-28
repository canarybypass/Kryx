"""
MITRE ATT&CK data fetcher for Hexor dataset
"""
import json
import httpx
import asyncio
from pathlib import Path

BASE = Path(__file__).parent.parent
MITRE_DIR = BASE / "mitre"
RAW = BASE / "raw"

ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


async def fetch_mitre() -> list[dict]:
    """Fetch MITRE ATT&CK enterprise techniques."""
    MITRE_DIR.mkdir(parents=True, exist_ok=True)

    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(ATTACK_URL)
        r.raise_for_status()
        data = r.json()

    # Save raw
    with open(RAW / "mitre_attack_raw.json", "w") as f:
        json.dump(data, f, indent=2)

    objects = data.get("objects", [])

    # Extract techniques (not sub-techniques for now)
    techniques = [
        obj for obj in objects
        if obj.get("type") == "attack-pattern"
        and not obj.get("x_mitre_is_subtechnique", False)
    ]

    result = []
    for t in techniques:
        external_refs = t.get("external_references", [])
        mitre_id = next(
            (ref["external_id"] for ref in external_refs if ref.get("source_name") == "mitre-attack"),
            "",
        )

        # Get procedure examples
        procedures = []
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack" and "url" in ref:
                pass  # We'll parse these differently

        result.append({
            "id": mitre_id,
            "name": t.get("name", ""),
            "description": t.get("description", ""),
            "tactics": [p["phase_name"] for p in t.get("kill_chain_phases", [])],
            "platforms": t.get("x_mitre_platforms", []),
            "detection": t.get("x_mitre_detection", ""),
        })

    print(f"  Fetched {len(result)} MITRE ATT&CK techniques")
    return result


def build_mitre_samples(techniques: list[dict]) -> list[dict]:
    """Convert MITRE techniques into training samples."""
    samples = []

    # Sample: describe the technique
    for t in techniques:
        if not t.get("description"):
            continue

        tactics_str = ", ".join(t.get("tactics", []))
        platforms_str = ", ".join(t.get("platforms", []))

        samples.append({
            "instruction": (
                f"Опиши технику MITRE ATT&CK {t.get('id', '')} — {t.get('name', '')}. "
                f"Как атакующий её применяет? Как защищающейся стороне обнаружить эту активность?"
            ),
            "input": (
                f"Technique: {t.get('id', '')} — {t.get('name', '')}\n"
                f"Tactics: {tactics_str}\n"
                f"Platforms: {platforms_str}"
            ),
            "output": (
                f"Техника {t.get('id', '')}: {t.get('name', '')}\n"
                f"Тактики: {tactics_str}\n"
                f"Платформы: {platforms_str}\n\n"
                f"Описание:\n{t.get('description', '')[:800]}\n\n"
                f"Применение атакующим:\n"
                f"Атакующий использует эту технику на этапе(ах): {tactics_str}. "
                f"Техника применима на платформах: {platforms_str}.\n\n"
                f"Обнаружение (detection):\n"
                f"{t.get('detection', 'Мониторинг логов, анализ сетевого трафика, поведенческий анализ.')[:500]}\n\n"
                f"Рекомендации пентестеру:\n"
                f"- При тестировании проверь возможность применения этой техники на целевых системах\n"
                f"- Используй инструменты, соответствующие платформе ({platforms_str})\n"
                f"- Задокументируй evidence применения техники для отчёта"
            ),
        })

    # Cross-tactic chain reasoning
    chain_samples = _build_chain_samples(techniques)
    samples.extend(chain_samples)

    return samples


def _build_chain_samples(techniques: list[dict]) -> list[dict]:
    """Build samples teaching how techniques chain together."""
    # Map tactics to techniques
    by_tactic = {}
    for t in techniques:
        for tactic in t.get("tactics", []):
            by_tactic.setdefault(tactic, []).append(t)

    samples = []

    # Build a sample: "how to chain from initial-access to exfiltration"
    chain_order = [
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "exfiltration",
    ]

    # Pick one technique per tactic for a sample chain
    chain_steps = []
    for tactic in chain_order:
        if tactic in by_tactic and by_tactic[tactic]:
            tech = by_tactic[tactic][0]
            chain_steps.append(f"{tech.get('id', '')} ({tactic}): {tech.get('name', '')}")

    if len(chain_steps) >= 5:
        samples.append({
            "instruction": "Построй цепочку атаки уровня APT от начального доступа до эксфильтрации данных, используя MITRE ATT&CK техники.",
            "input": "Построй kill chain от initial access до exfiltration",
            "output": (
                "Цепочка атаки APT (MITRE ATT&CK):\n\n"
                + "\n".join(f"{i+1}. {step}" for i, step in enumerate(chain_steps))
                + "\n\n"
                "Эта цепочка демонстрирует полный цикл атаки:\n"
                "1. Начальный доступ (Initial Access) — проникновение в сеть\n"
                "2. Выполнение (Execution) — запуск вредоносного кода\n"
                "3. Закрепление (Persistence) — сохранение доступа\n"
                "4. Повышение привилегий (Privilege Escalation)\n"
                "5. Обход защиты (Defense Evasion) — скрытие активности\n"
                "6. Доступ к учётным данным (Credential Access)\n"
                "7. Разведка (Discovery) — изучение сети\n"
                "8. Боковое перемещение (Lateral Movement)\n"
                "9. Сбор данных (Collection)\n"
                "10. Эксфильтрация (Exfiltration)\n\n"
                "Для пентестера: проверь возможность выполнения каждого шага цепочки.\n"
                "Если какой-то шаг невозможен — цепочка прерывается.\n"
                "Документируй какие техники удалось применить."
            ),
        })

    return samples


async def main():
    print("Fetching MITRE ATT&CK data...")
    techniques = await fetch_mitre()
    samples = build_mitre_samples(techniques)

    # Save
    out = BASE / "processed"
    out.mkdir(parents=True, exist_ok=True)

    with open(out / "mitre_samples.jsonl", "w") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    print(f"  Built {len(samples)} MITRE training samples")

    return samples


if __name__ == "__main__":
    asyncio.run(main())