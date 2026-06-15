#!/usr/bin/env python3
"""
Kryx Benchmark CLI — запуск benchmark из терминала
Usage:
  python benchmark.py                    # все цели
  python benchmark.py --difficulty easy  # только easy цели
  python benchmark.py --targets "DVWA" "Juice Shop"  # конкретные цели
"""
import asyncio
import argparse
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

from benchmark.runner import run_benchmark


async def main():
    parser = argparse.ArgumentParser(description="Kryx Benchmark — оценка качества агента")
    parser.add_argument(
        "--targets",
        nargs="+",
        help="Список имён целей (например: DVWA 'OWASP Juice Shop')",
    )
    parser.add_argument(
        "--difficulty",
        choices=["beginner", "intermediate", "advanced"],
        help="Фильтр по сложности",
    )
    parser.add_argument(
        "--max-hunters",
        type=int,
        default=8,
        help="Максимум параллельных hunter агентов (default: 8)",
    )
    parser.add_argument(
        "--output",
        help="Сохранить результаты в JSON файл",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("HEXOR BENCHMARK")
    print("=" * 60)
    print()

    if args.targets:
        print(f"Targets: {', '.join(args.targets)}")
    elif args.difficulty:
        print(f"Difficulty: {args.difficulty}")
    else:
        print("Running on ALL targets")

    print(f"Max hunters: {args.max_hunters}")
    print()

    result = await run_benchmark(
        target_names=args.targets,
        difficulty=args.difficulty,
        max_hunters=args.max_hunters,
    )

    if "error" in result:
        print(f"Error: {result['error']}")
        sys.exit(1)

    # Print summary
    print()
    print(result["summary"])
    print()

    # Print per-target results
    print("=" * 60)
    print("PER-TARGET RESULTS")
    print("=" * 60)
    for r in result["results"]:
        status_icon = "✓" if r["status"] == "done" else "✗"
        print(f"\n{status_icon} {r['target']}")
        print(f"  URL: {r['url']}")
        print(f"  Status: {r['status']}")
        if r["status"] == "done":
            m = r["metrics"]
            print(f"  Findings: {r['findings_count']}")
            print(f"  TP: {m['true_positives']}, FP: {m['false_positives']}, FN: {m['false_negatives']}")
            print(f"  Precision: {m['precision']:.1%}, Recall: {m['recall']:.1%}, F1: {m['f1_score']:.3f}")
        elif r["error"]:
            print(f"  Error: {r['error']}")

    # Save to file if requested
    if args.output:
        import json
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
