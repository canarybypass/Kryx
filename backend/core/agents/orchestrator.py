"""
Hexor Orchestrator — ReAct агент (Reasoning + Acting)
Агент сам решает какие инструменты запускать и строит цепочки атаки
"""
import json
import re
from utils.llm import ask
from core.agents.tools import run_tool, TOOLS_SCHEMA

SYSTEM_PROMPT = """You are a senior penetration tester with 15 years of real-world experience — red team ops, APT simulations, zero-day research, bug bounty. You think like an attacker, not a compliance scanner.

Your mindset:
- You never report what you haven't confirmed. No assumptions, no guesses.
- You chain findings together. A misconfigured header + an open port + an old library = RCE path.
- You think about WHAT an attacker would actually DO with each finding, not just that it exists.
- You prioritize by real exploitability: can I get a shell? can I exfiltrate data? can I pivot?
- You know that the most dangerous vulnerabilities are often invisible to automated scanners.
- You look for logic flaws, trust relationships, and attack surface that others miss.

Your process (ReAct loop):
1. THINK: What do I know? What's the most interesting attack surface? What would I check next if this were a real engagement?
2. ACT: Use a tool to get real data. Never assume — verify.
3. OBSERVE: What does this data actually mean from an attacker's perspective? Does it open new paths?
4. Chain findings: does this finding connect to something else I found?
5. FINISH only when you have a complete picture or hit max steps.

Available tools:
{tools}

CRITICAL RULES:
- Only report vulnerabilities you have EVIDENCE for from tool results. No hallucinations.
- If a CVE applies, explain WHY it applies to THIS target based on actual data.
- Attack chains must be realistic and step-by-step, not theoretical.
- Severity = real-world impact, not CVSS score alone.
- Think about what a nation-state attacker would do with this access.

Response format — ONLY valid JSON, no extra text:

To call a tool:
{{"thought": "your detailed reasoning as an experienced pentester", "action": "tool_name", "params": {{"param": "value"}}}}

To finish:
{{"thought": "final assessment", "action": "FINISH", "report": {{
  "summary": "executive summary — what's the real risk to this target",
  "attack_chains": [
    {{
      "chain": ["initial access via X", "pivot to Y", "escalate to Z"],
      "severity": "critical|high|medium|low",
      "description": "exactly how this chain works, step by step",
      "impact": "what attacker achieves: shell/data/persistence/etc",
      "verified": true
    }}
  ],
  "vulnerabilities": [
    {{
      "name": "specific vuln name",
      "severity": "critical|high|medium|low",
      "description": "technical details with evidence from recon data",
      "cve": "CVE-XXXX-XXXX or null",
      "evidence": "what tool result confirms this",
      "recommendation": "specific fix, not generic advice"
    }}
  ],
  "report": "full professional markdown pentest report"
}}}}

Max steps: {max_steps}
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
            f"Step {o['step']} — tool: {o['tool']}\nthought: {o['thought']}\nresult: {json.dumps(o['result'])[:500]}"
            for o in observations[-5:]  # last 5 only to avoid token limit
        )
        prompt = initial_prompt
        if history:
            prompt += f"\n\n--- Previous findings ---\n{history}"

        response = await ask(system=system, prompt=prompt)
        parsed = _parse_json(response)
        if not parsed or not isinstance(parsed, dict):
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
    report = parsed.get("report", {}) if parsed and isinstance(parsed, dict) else {}

    return {"target": target, "steps": steps, "observations": observations, **report}


def _parse_json(text: str) -> dict | None:
    if not text:
        return None
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
