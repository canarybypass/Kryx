import json
from utils.llm import ask


class ReporterAgent:
    async def run(self, target: str, recon_data: dict, vulnerabilities: list) -> str:
        report = await ask(
            system=(
                "You are a professional penetration testing report writer. "
                "Write a clear, structured security assessment report in markdown format. "
                "Include: Executive Summary, Scope, Findings (with severity), Recommendations."
            ),
            prompt=(
                f"Target: {target}\n"
                f"Recon Summary: {recon_data.get('summary', '')}\n"
                f"Vulnerabilities: {json.dumps(vulnerabilities, indent=2)}\n\n"
                "Write the full penetration test report."
            ),
        )
        return report
