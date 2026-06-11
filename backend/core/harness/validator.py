"""
Hexor Validator Stage — adversarial review of findings
"""
import json
import asyncio
from utils.llm import get_llm
from core.agents.prompts import VALIDATOR_PROMPT


class ValidatorStage:
    """Stage 3: независимая проверка находок."""

    def __init__(self, target: str, recon: dict, findings: list):
        self.target = target
        self.recon = recon
        self.findings = findings

    async def run(self) -> list:
        if not self.findings:
            return []

        llm = get_llm()

        # Validate each finding in parallel
        tasks = [self._validate(f, llm) for f in self.findings]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        validated = []
        for finding, result in zip(self.findings, results):
            if isinstance(result, Exception):
                # Validator errored — don't silently lose a tool-confirmed bug.
                if finding.get("exploitability") == "confirmed":
                    finding["validation_note"] = "validator error; kept (tool-confirmed)"
                    validated.append(finding)
                continue

            verdict = result.get("verdict")

            if verdict == "confirmed":
                finding["validated"] = True
                if result.get("adjusted_severity"):
                    finding["severity"] = result["adjusted_severity"]
                validated.append(finding)

            elif verdict == "rejected":
                # Explicit hallucination call — drop it.
                continue

            elif finding.get("exploitability") == "confirmed":
                # Validator was merely unsure (needs_more_evidence / unparsed),
                # but the hunter confirmed this with a tool. A deterministic tool
                # verdict is a fact, not an opinion — keep it rather than lose a
                # real bug to model variance. Flag it as needing a second look.
                finding["validated"] = True
                finding["validation_note"] = f"tool-confirmed; validator: {verdict or 'unparsed'}"
                validated.append(finding)

        return validated

    async def _validate(self, finding: dict, llm) -> dict:
        prompt = f"""Target: {self.target}

Finding to validate:
{json.dumps(finding, indent=2, ensure_ascii=False)}

Context (recon data):
{json.dumps(self.recon, indent=2, ensure_ascii=False)[:1500]}

Critically review this finding. Is it REAL or HALLUCINATED?"""

        response = await llm.ask(VALIDATOR_PROMPT, prompt)
        return _parse_json(response) or {"verdict": "needs_more_evidence"}


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