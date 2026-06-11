"""
Hexor Hunter Stage — параллельные агенты для поиска уязвимостей
"""
import json
import asyncio
from utils.llm import get_llm
from core.agents.prompts import HUNTER_PROMPT
from core.tools.scanner import run_tool, TOOLS_SCHEMA
from core.harness.memory import AgentMemory


# Attack classes for parallel hunting
ATTACK_CLASSES = [
    {
        "name": "injection",
        "description": "SQL injection, command injection, LDAP injection, XXE",
        "tools": ["sqlmap_check", "http_probe", "browser_probe"],
        "priority": "critical",
    },
    {
        "name": "xss_csrf",
        "description": "Reflected/stored/DOM XSS, CSRF vulnerabilities",
        "tools": ["xss_probe", "http_probe", "browser_probe"],
        "priority": "high",
    },
    {
        "name": "auth_session",
        "description": "Authentication bypass, session fixation, JWT issues, weak password policies",
        "tools": ["http_probe", "dir_bruteforce", "browser_probe"],
        "priority": "critical",
    },
    {
        "name": "config_exposure",
        "description": "Exposed config files, .git, .env, backup files, debug endpoints",
        "tools": ["sensitive_files", "dir_bruteforce", "http_probe", "nuclei_scan"],
        "priority": "high",
    },
    {
        "name": "cors_ssrf",
        "description": "CORS misconfig, SSRF, open redirect, server-side request issues",
        "tools": ["http_probe", "nuclei_scan", "browser_probe"],
        "priority": "high",
    },
    {
        "name": "network_services",
        "description": "Open ports, service vulnerabilities, default credentials",
        "tools": ["nmap_scan", "ssl_audit", "nuclei_scan", "shodan_lookup", "censys_lookup"],
        "priority": "high",
    },
    {
        "name": "info_disclosure",
        "description": "Information leakage, verbose errors, exposed APIs, swagger/graphql",
        "tools": ["sensitive_files", "dir_bruteforce", "http_probe", "whatweb", "browser_probe"],
        "priority": "medium",
    },
    {
        "name": "dependency_cve",
        "description": "Known CVEs in detected technologies and versions",
        "tools": ["cve_lookup", "whatweb", "nuclei_scan", "shodan_lookup", "msf_search"],
        "priority": "high",
    },
]


class HunterStage:
    """Stage 2: параллельный поиск уязвимостей."""

    def __init__(self, target: str, recon: dict, max_hunters: int, emit_cb=None):
        self.target = target
        self.recon = recon
        self.max_hunters = max_hunters
        self.emit = emit_cb

    async def run(self) -> list:
        # Select relevant attack classes based on recon
        tasks = self._select_attack_classes()[: self.max_hunters]

        # Run hunters in parallel
        hunters = [self._run_hunter(task) for task in tasks]
        results = await asyncio.gather(*hunters, return_exceptions=True)

        # Collect findings
        all_findings = []
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                continue
            for finding in r:
                finding["attack_class"] = tasks[i]["name"]
                all_findings.append(finding)

        return all_findings

    def _select_attack_classes(self) -> list:
        # Always include high-priority classes
        selected = [c for c in ATTACK_CLASSES if c["priority"] in ("critical", "high")]

        # Add medium-priority if slots remain
        if len(selected) < self.max_hunters:
            medium = [c for c in ATTACK_CLASSES if c["priority"] == "medium"]
            selected.extend(medium[: self.max_hunters - len(selected)])

        return selected

    async def _run_hunter(self, attack_class: dict) -> list:
        llm = get_llm()
        memory = AgentMemory(attack_class=attack_class["name"], target=self.target)

        tools_desc = "\n".join(
            f"- {t['name']}({', '.join(f'{k}: {v}' for k, v in t['parameters'].items())}): {t['description']}"
            for t in TOOLS_SCHEMA
            if t["name"] in attack_class["tools"]
        )

        base_context = (
            f"Target: {self.target}\n"
            f"Attack class: {attack_class['name']} — {attack_class['description']}\n"
            f"Available tools: {', '.join(attack_class['tools'])}\n\n"
            f"Recon data:\n{json.dumps(self.recon, indent=2, ensure_ascii=False)[:2000]}"
        )

        max_steps = 8  # увеличили с 6 до 8

        for step in range(max_steps):
            # Build prompt with full memory
            memory_text = memory.to_prompt()
            replan_hint = memory.replan_hint() if memory.should_replan() else ""

            prompt = (
                f"{base_context}\n\n"
                f"{memory_text}\n\n"
                f"{replan_hint}\n"
                f"Текущий шаг: {step + 1}/{max_steps}"
            ).strip()

            system = HUNTER_PROMPT.format(
                tools=tools_desc,
                context=base_context,
                max_steps=max_steps,
                step=step + 1,
            )

            response = await llm.ask(system, prompt)
            parsed = _parse_json(response)

            if not parsed or not isinstance(parsed, dict):
                continue

            # Extract hypothesis if present
            if parsed.get("thought"):
                memory.add_hypothesis(parsed["thought"][:200])

            action = parsed.get("action")

            if action == "FINISH":
                findings = parsed.get("findings", [])
                for f in findings:
                    memory.add_finding(f)
                return findings

            if not action:
                continue

            # Skip if already tried exact same call
            params = parsed.get("params", {})
            if memory.already_tried(action, params):
                # Force agent to try something else next step
                memory.failed_tools.append(action)
                continue

            # Execute tool
            result = await run_tool(action, params)
            memory.add_observation(
                step=step + 1,
                thought=parsed.get("thought", ""),
                tool=action,
                params=params,
                result=result,
            )

            if self.emit:
                await self.emit("hunter_step", {
                    "attack_class": attack_class["name"],
                    "step": step + 1,
                    "tool": action,
                    "thought": parsed.get("thought", ""),
                    "useful": memory.observations[-1].useful,
                })

        # Timeout — return whatever findings memory has
        return memory.findings


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