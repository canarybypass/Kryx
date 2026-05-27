"""
Hexor Recon Stage — первичная разведка цели
"""
import json
from utils.llm import get_llm
from core.agents.prompts import RECON_PROMPT
from core.tools.scanner import run_tool


class ReconStage:
    """Stage 1: карта поверхности атаки."""

    def __init__(self, target: str):
        self.target = target
        self.domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    async def run(self) -> dict:
        llm = get_llm()

        # Run quick passive recon tools in parallel
        dns_task = run_tool("dns_lookup", {"domain": self.domain})
        whois_task = run_tool("whois_lookup", {"domain": self.domain})
        http_task = run_tool("http_probe", {"url": self.target})

        dns, whois, http = await asyncio_get(
            dns_task, whois_task, http_task
        )

        raw_data = {
            "dns": dns,
            "whois": whois,
            "http_probe": http,
        }

        # Ask LLM to structure the recon data
        prompt = f"""Target: {self.target}
Domain: {self.domain}

Raw recon data:
{json.dumps(raw_data, indent=2, ensure_ascii=False)}

Analyze and structure the attack surface."""

        response = await llm.ask(RECON_PROMPT, prompt)
        parsed = _parse_json(response)

        if parsed:
            parsed["raw_tools"] = raw_data
            return parsed

        return {"target": self.target, "domain": self.domain, "raw_tools": raw_data}


async def asyncio_get(*coros):
    import asyncio
    results = await asyncio.gather(*coros, return_exceptions=True)
    return [r if not isinstance(r, Exception) else {"error": str(r)} for r in results]


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