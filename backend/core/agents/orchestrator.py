"""
Hexor Orchestrator — ReAct агент (Reasoning + Acting)
Агент сам решает какие инструменты запускать и строит цепочки атаки
"""
import json
import re
from utils.llm import ask
from core.agents.tools import run_tool, TOOLS_SCHEMA

SYSTEM_PROMPT = """You are Hexor — an elite autonomous penetration testing agent.

Your job: analyze a target and find ALL vulnerabilities, misconfigurations, and attack chains.

You work in a ReAct loop:
1. THINK: reason about what you know and what to investigate next
2. ACT: call a tool to gather data
3. OBSERVE: analyze the result
4. Repeat until you have enough data to build a complete attack chain report

Available tools:
{tools}

Response format — always respond with valid JSON in one of these formats:

To call a tool:
{{"thought": "your reasoning", "action": "tool_name", "params": {{"param": "value"}}}}

To finish and report:
{{"thought": "final reasoning", "action": "FINISH", "report": {{
  "summary": "executive summary",
  "attack_chains": [
    {{
      "chain": ["step1", "step2", "step3"],
      "severity": "critical|high|medium|low",
      "description": "how this chain works",
      "impact": "what attacker can achieve"
    }}
  ],
  "vulnerabilities": [
    {{
      "name": "vuln name",
      "severity": "critical|high|medium|low",
      "description": "technical details",
      "cve": "CVE-XXXX-XXXX or null",
      "recommendation": "how to fix"
    }}
  ],
  "report": "full markdown report"
}}}}

Rules:
- Think like an APT group, not a script kiddie
- Build attack chains: how one finding leads to another
- Prioritize by real exploitability, not just CVSS score
- Max {max_steps} steps, then FINISH
- Be specific: versions, CVEs, exact misconfigs
"""


async def run_agent(target: str, max_steps: int = 10) -> dict:
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    tools_desc = "\n".join(
        f"- {t['name']}({', '.join(f'{k}: {v}' for k, v in t['parameters'].items())}): {t['description']}"
        for t in TOOLS_SCHEMA
    )

    system = SYSTEM_PROMPT.format(tools=tools_desc, max_steps=max_steps)
    observations = []
    steps = 0

    initial_prompt = f"Target: {target} (domain: {domain})\n\nBegin reconnaissance and vulnerability analysis."

    while steps < max_steps:
        steps += 1

        history = "\n\n".join(
            f"Step {i+1} — tool: {o['tool']}, thought: {o['thought']}\nresult: {json.dumps(o['result'], indent=2)}"
            for i, o in enumerate(observations)
        )
        prompt = initial_prompt
        if history:
            prompt += f"\n\n--- Previous findings ---\n{history}"

        response = await ask(system=system, prompt=prompt)
        parsed = _parse_json(response)
        if not parsed:
            continue

        action = parsed.get("action")

        if action == "FINISH":
            report = parsed.get("report", {})
            return {"target": target, "steps": steps, "observations": observations, **report}

        # Execute tool
        result = await run_tool(action, parsed.get("params", {}))
        observations.append({
            "step": steps,
            "thought": parsed.get("thought", ""),
            "tool": action,
            "params": parsed.get("params", {}),
            "result": result,
        })

    # Max steps reached — force final report
    summary_prompt = (
        f"Target: {target}\nAll findings:\n{json.dumps(observations, indent=2)}\n\n"
        "Produce the final FINISH report with attack_chains and vulnerabilities."
    )
    final = await ask(system=system, prompt=summary_prompt)
    parsed = _parse_json(final)
    report = parsed.get("report", {}) if parsed else {}

    return {"target": target, "steps": steps, "observations": observations, **report}


def _parse_json(text: str) -> dict | None:
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
