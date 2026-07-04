"""
Benchmark Runner - запуск агента на каждой цели и сбор метрик
"""
import asyncio
from datetime import datetime
from dataclasses import dataclass, field

from core.harness.supervisor import Supervisor
from benchmark.targets import BENCHMARK_TARGETS
from benchmark.metrics import calculate_metrics, aggregate_metrics, BenchmarkMetrics


@dataclass
class BenchmarkResult:
    target_name: str
    target_url: str
    started_at: datetime
    finished_at: datetime | None = None
    status: str = "running"  # running|done|error
    agent_findings: list = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    error: str | None = None


class BenchmarkRunner:
    """Запускает агента на списке целей и собирает метрики."""

    def __init__(self, targets: list[dict] | None = None, max_hunters: int = 8, progress_cb=None):
        self.targets = targets or BENCHMARK_TARGETS
        self.max_hunters = max_hunters
        self.progress_cb = progress_cb
        self.results: list[BenchmarkResult] = []

    async def run(self) -> dict:
        """Запустить benchmark на всех целях."""
        await self._emit("status", "started")
        await self._emit("total_targets", len(self.targets))

        for idx, target in enumerate(self.targets):
            await self._emit("current_target", {
                "index": idx + 1,
                "total": len(self.targets),
                "name": target["name"],
                "url": target["url"],
            })

            result = await self._run_single_target(target)
            self.results.append(result)

            await self._emit("target_complete", {
                "target": target["name"],
                "status": result.status,
                "metrics": result.metrics,
            })

        # Aggregate metrics
        aggregate = aggregate_metrics([
            {
                "target": r.target_name,
                "metrics": r.metrics,
            }
            for r in self.results
        ])

        await self._emit("status", "done")

        return {
            "started_at": self.results[0].started_at.isoformat() if self.results else None,
            "finished_at": datetime.utcnow().isoformat(),
            "total_targets": len(self.targets),
            "results": [self._result_to_dict(r) for r in self.results],
            "aggregate_metrics": aggregate["aggregate"],
            "summary": self._generate_summary(aggregate),
        }

    async def _run_single_target(self, target: dict) -> BenchmarkResult:
        """Запустить агента на одной цели."""
        result = BenchmarkResult(
            target_name=target["name"],
            target_url=target["url"],
            started_at=datetime.utcnow(),
        )

        try:
            # Run agent
            supervisor = Supervisor(target["url"], max_hunters=self.max_hunters)
            scan_result = await supervisor.run()

            result.agent_findings = scan_result.get("vulnerabilities", [])
            result.status = "done"
            result.finished_at = datetime.utcnow()

            # Calculate metrics
            metrics = calculate_metrics(target["ground_truth"], result.agent_findings)
            result.metrics = metrics.to_dict()

        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.finished_at = datetime.utcnow()

        return result

    def _result_to_dict(self, r: BenchmarkResult) -> dict:
        return {
            "target": r.target_name,
            "url": r.target_url,
            "status": r.status,
            "started_at": r.started_at.isoformat(),
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            "findings_count": len(r.agent_findings),
            "metrics": r.metrics,
            "error": r.error,
        }

    def _generate_summary(self, aggregate: dict) -> str:
        """Генерировать текстовое резюме результатов."""
        m = aggregate["aggregate"]
        
        summary_lines = [
            f"Benchmark завершён: {len(self.results)} целей протестировано",
            f"",
            f"Агрегированные метрики:",
            f"  True Positives:  {m['true_positives']}",
            f"  False Positives: {m['false_positives']}",
            f"  False Negatives: {m['false_negatives']}",
            f"",
            f"  Precision: {m['precision']:.1%}",
            f"  Recall:    {m['recall']:.1%}",
            f"  F1 Score:  {m['f1_score']:.3f}",
            f"  FP Rate:   {m['false_positive_rate']:.1%}",
        ]

        # Оценка качества
        f1 = m["f1_score"]
        if f1 >= 0.9:
            grade = "Отлично"
        elif f1 >= 0.75:
            grade = "Хорошо"
        elif f1 >= 0.5:
            grade = "Удовлетворительно"
        else:
            grade = "Требует улучшения"

        summary_lines.append(f"\nОбщая оценка: {grade}")

        return "\n".join(summary_lines)

    async def _emit(self, event: str, data):
        if self.progress_cb:
            await self.progress_cb({"event": event, "data": data})


async def run_benchmark(
    target_names: list[str] | None = None,
    difficulty: str | None = None,
    max_hunters: int = 8,
) -> dict:
    """
    Запустить benchmark.
    
    target_names: список имён целей (если None - все)
    difficulty: фильтр по сложности (beginner/intermediate/advanced)
    """
    from benchmark.targets import get_target_by_name, get_targets_by_difficulty

    if target_names:
        targets = [get_target_by_name(name) for name in target_names]
        targets = [t for t in targets if t is not None]
    elif difficulty:
        targets = get_targets_by_difficulty(difficulty)
    else:
        targets = BENCHMARK_TARGETS

    if not targets:
        return {"error": "No targets selected"}

    runner = BenchmarkRunner(targets=targets, max_hunters=max_hunters)
    return await runner.run()
