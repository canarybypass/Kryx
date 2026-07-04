"""
Kryx Reporter - генерация профессионального отчёта.

The report is grounded strictly in the scan data: the LLM is given the real
tool-chain that actually ran, today's date, and the deduplicated findings, and
is told (in REPORTER_PROMPT) to invent nothing. This stops the writer from
fabricating a methodology section with tools we don't ship (ffuf, Burp, etc.),
placeholder dates, or duplicate findings.
"""
import json
from datetime import date
from utils.llm import get_llm
from core.agents.prompts import REPORTER_PROMPT

# The actual black-box web tool-chain every scan drives. The report's
# "Методология" section must list these and ONLY these - never invent others.
WEB_TOOLCHAIN = [
    "nmap (порты/сервисы)",
    "subfinder + crt.sh (поддомены, certificate transparency)",
    "whatweb (фингерпринт стека)",
    "Playwright / headless Chromium (краулинг, DOM, JS-эндпоинты)",
    "nuclei (шаблонные детекторы CVE/мисконфигов)",
    "sqlmap (SQL-инъекции)",
    "проприетарные пробы Kryx (XSS, SSTI, IDOR/BOLA, LFI/RFI, CMDi, SSRF, Open-Redirect, HTTP)",
    "аудит SSL/TLS",
    "состязательная валидация Kryx (attacker-vs-defender debate)",
]

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "": 0, None: 0}
# A finding is part of the "exposure" family when its name/type hints at a file/
# config/secret being directly reachable. Two such hits on the same URL are the
# same real issue (e.g. /config.json flagged by two nuclei templates) and must
# collapse into one report entry.
_EXPOSURE_HINTS = (
    "config", "file", ".git", ".svn", ".env", "backup", "dump",
    "exposure", "exposed", "disclosure", "listing", "directory",
)


def _loc(f: dict) -> str:
    return (f.get("url") or f.get("location") or f.get("file") or "").strip().rstrip("/").lower()


def _is_exposure(f: dict) -> bool:
    blob = f"{f.get('type', '')} {f.get('name', '')} {f.get('vtype', '')}".lower()
    return any(h in blob for h in _EXPOSURE_HINTS)


def _dedupe_for_report(findings: list) -> list:
    """Collapse exposure-family findings that point at the same location,
    keeping the highest-severity one. Non-exposure findings pass through
    untouched (distinct vulns are never merged)."""
    best: dict = {}
    passthrough: list = []
    for f in findings:
        if _is_exposure(f) and _loc(f):
            key = _loc(f)
            cur = best.get(key)
            if cur is None or _SEV_RANK.get(f.get("severity")) > _SEV_RANK.get(cur.get("severity")):
                best[key] = f
        else:
            passthrough.append(f)
    return list(best.values()) + passthrough


class ReporterStage:
    """Stage 5: генерация финального отчёта."""

    def __init__(self, target: str, result):
        self.target = target
        self.result = result

    async def run(self) -> tuple[str, str]:
        llm = get_llm()

        findings = _dedupe_for_report(self.result.validated_findings)
        data = {
            "target": self.result.target,
            "date": date.today().isoformat(),
            "scan_type": "black-box (без доступа к исходному коду)",
            "tools_used": WEB_TOOLCHAIN,
            "recon": self.result.recon,
            "vulnerabilities": findings,
            "attack_chains": self.result.attack_chains,
        }

        prompt = f"""Данные скана для {self.target}:

{json.dumps(data, indent=2, ensure_ascii=False)}

Напиши полный профессиональный отчёт о пентесте на русском (markdown), строго
по этим данным. В разделе «Методология» перечисли инструменты РОВНО из поля
"tools_used" и ничего больше. Дату возьми из "date". Если находок нет -
честно напиши, что подтверждённых уязвимостей не выявлено, и не выдумывай их."""

        report = await llm.ask(REPORTER_PROMPT, prompt, json_mode=False)

        # Executive summary - also grounded strictly in the data.
        summary_prompt = f"""Данные скана:

{json.dumps({k: data[k] for k in ('target', 'vulnerabilities', 'attack_chains')}, ensure_ascii=False)[:2000]}

Напиши executive summary в 2-3 предложениях на русском. Только по данным выше,
без выдумок. Если уязвимостей нет - так и скажи."""

        summary = await llm.ask(
            "Ты пишешь executive summary отчёта о пентесте. 2-3 предложения на русском. "
            "Конкретно, строго по данным, без воды и без выдумок.",
            summary_prompt,
            json_mode=False,
        )

        return report, summary
