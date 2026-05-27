"""
Hexor Reporter — генерация профессионального отчёта
"""
import json
from utils.llm import get_llm
from core.agents.prompts import REPORTER_PROMPT


class ReporterStage:
    """Stage 5: генерация финального отчёта."""

    def __init__(self, target: str, result):
        self.target = target
        self.result = result

    async def run(self) -> tuple[str, str]:
        llm = get_llm()

        data = {
            "target": self.result.target,
            "recon": self.result.recon,
            "vulnerabilities": self.result.validated_findings,
            "attack_chains": self.result.attack_chains,
        }

        prompt = f"""Scan results for {self.target}:

{json.dumps(data, indent=2, ensure_ascii=False)}

Write the full professional penetration test report in Russian markdown."""

        report = await llm.ask(REPORTER_PROMPT, prompt, json_mode=False)

        # Generate executive summary
        summary_prompt = f"""Based on these scan results, write a 2-3 sentence executive summary in Russian:

{json.dumps(data, indent=2, ensure_ascii=False)[:2000]}"""

        summary = await llm.ask(
            "Ты пишешь executive summary отчёта о пентесте. 2-3 предложения на русском. Конкретно, без воды.",
            summary_prompt,
            json_mode=False,
        )

        return report, summary