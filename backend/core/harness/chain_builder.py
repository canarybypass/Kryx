"""
Kryx Chain Builder - построение цепочек атак из подтверждённых уязвимостей
"""
import json
from utils.llm import get_llm
from core.agents.prompts import CHAIN_BUILDER_PROMPT


class ChainBuilderStage:
    """Stage 4: строим attack chains."""

    def __init__(self, target: str, validated_findings: list):
        self.target = target
        self.findings = validated_findings

    async def run(self) -> list:
        if not self.findings:
            return []

        llm = get_llm()

        prompt = f"""Target: {self.target}

Confirmed vulnerabilities:
{json.dumps(self.findings, indent=2, ensure_ascii=False)}

Build realistic attack chains. Combine vulnerabilities where possible.
Think like an APT-level attacker: what's the most damaging path to compromise?"""

        response = await llm.ask(CHAIN_BUILDER_PROMPT, prompt)
        parsed = _parse_json(response)

        if parsed and "attack_chains" in parsed:
            return parsed["attack_chains"]

        return []


def _parse_json(text: str) -> dict | None:
    import re
    try:
        return json.loads(text)
    except Exception:
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except Exception:
                pass
    return None