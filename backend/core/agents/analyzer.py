import json
from utils.llm import ask


class AnalyzerAgent:
    async def run(self, recon_data: dict) -> list:
        response = await ask(
            system=(
                "You are an expert penetration tester. Based on recon data, identify potential vulnerabilities. "
                "Return a JSON array of findings. Each finding: {name, severity, description, recommendation}. "
                "Severity: critical | high | medium | low. Return ONLY valid JSON array, no markdown."
            ),
            prompt=f"Recon data:\n{json.dumps(recon_data, indent=2)}\n\nList all potential vulnerabilities.",
        )
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return [{"name": "Parse error", "severity": "low", "description": response, "recommendation": ""}]
