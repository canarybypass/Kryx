"""
AgentMemory - persistent memory для hunter агентов.
Хранит всё что агент пробовал, нашёл, и что не сработало.
Используется для adaptive replanning.
"""
from dataclasses import dataclass, field


@dataclass
class Observation:
    step: int
    thought: str
    tool: str
    params: dict
    result: dict
    useful: bool = True   # помечается False если результат пустой/ошибка


@dataclass
class AgentMemory:
    """
    Полная память агента за всю сессию охоты.
    Передаётся в промпт на каждом шаге - агент всегда видит полный контекст.
    """
    attack_class: str
    target: str

    observations: list[Observation] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    failed_tools: list[str] = field(default_factory=list)   # инструменты вернувшие ошибку
    tried_params: list[dict] = field(default_factory=list)  # параметры которые уже пробовали
    hypotheses: list[str] = field(default_factory=list)     # текущие гипотезы агента

    def add_observation(self, step: int, thought: str, tool: str, params: dict, result: dict):
        useful = self._is_useful(result)
        obs = Observation(step=step, thought=thought, tool=tool, params=params, result=result, useful=useful)
        self.observations.append(obs)

        if not useful:
            self.failed_tools.append(tool)

        # Track tried params to avoid repetition
        self.tried_params.append({"tool": tool, "params": params})

    def already_tried(self, tool: str, params: dict) -> bool:
        """Проверить не пробовали ли уже этот вызов."""
        for t in self.tried_params:
            if t["tool"] == tool and t["params"] == params:
                return True
        return False

    def add_finding(self, finding: dict):
        self.findings.append(finding)

    def add_hypothesis(self, hypothesis: str):
        if hypothesis and hypothesis not in self.hypotheses:
            self.hypotheses.append(hypothesis)

    def to_prompt(self) -> str:
        """Сериализовать память в текст для промпта."""
        parts = []

        if self.observations:
            parts.append("=== ЧТО УЖЕ СДЕЛАНО ===")
            for obs in self.observations:
                status = "✓" if obs.useful else "✗ (пусто/ошибка)"
                result_preview = _truncate(obs.result, 400)
                parts.append(
                    f"Шаг {obs.step} {status}: {obs.tool}({_params_str(obs.params)})\n"
                    f"  Мысль: {obs.thought[:150]}\n"
                    f"  Результат: {result_preview}"
                )

        if self.findings:
            parts.append("\n=== УЖЕ НАЙДЕНО ===")
            for f in self.findings:
                parts.append(f"  • [{f.get('severity','?').upper()}] {f.get('name','?')}: {f.get('description','')[:100]}")

        if self.failed_tools:
            failed_unique = list(dict.fromkeys(self.failed_tools))  # dedupe, preserve order
            parts.append(f"\n=== НЕ СРАБОТАЛО === {', '.join(failed_unique)}")

        if self.hypotheses:
            parts.append("\n=== ТЕКУЩИЕ ГИПОТЕЗЫ ===")
            for h in self.hypotheses:
                parts.append(f"  • {h}")

        return "\n".join(parts)

    def should_replan(self) -> bool:
        """Нужен ли replanning - слишком много пустых результатов подряд."""
        if len(self.observations) < 2:
            return False
        last_two = self.observations[-2:]
        return all(not o.useful for o in last_two)

    def replan_hint(self) -> str:
        """Подсказка для replanning на основе того что не сработало."""
        if not self.failed_tools:
            return ""
        failed = list(dict.fromkeys(self.failed_tools))
        available_tools = self._suggest_alternatives(failed)
        return (
            f"REPLANNING: инструменты {failed} не дали результатов. "
            f"Попробуй другой подход: {available_tools}"
        )

    def _suggest_alternatives(self, failed: list[str]) -> str:
        alternatives = {
            "sqlmap_check": "попробуй http_probe для ручного поиска SQLi параметров",
            "nuclei_scan": "попробуй dir_bruteforce или http_probe",
            "dir_bruteforce": "попробуй browser_probe для JS-rendered контента",
            "nmap_scan": "попробуй shodan_lookup или censys_lookup для пассивной разведки",
            "browser_probe": "попробуй http_probe с curl-style запросами",
        }
        hints = [alternatives[t] for t in failed if t in alternatives]
        return "; ".join(hints) if hints else "смени вектор атаки"

    @staticmethod
    def _is_useful(result: dict) -> bool:
        if "error" in result:
            return False
        # Empty results
        if result.get("open_ports") == [] and result.get("findings") == []:
            return False
        if result.get("found") == [] and result.get("count") == 0:
            return False
        if result.get("cves") == [] and result.get("total") == 0:
            return False
        return True


def _params_str(params: dict) -> str:
    return ", ".join(f"{k}={str(v)[:40]}" for k, v in params.items())


def _truncate(result: dict, max_len: int) -> str:
    import json
    try:
        s = json.dumps(result, ensure_ascii=False)
        return s[:max_len] + ("..." if len(s) > max_len else "")
    except Exception:
        return str(result)[:max_len]
