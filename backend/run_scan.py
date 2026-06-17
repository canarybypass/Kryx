"""
Kryx — standalone engine runner.

Runs the multi-agent Supervisor directly against a target, bypassing the
FastAPI server and PostgreSQL. Used to smoke-test the engine end-to-end.

Usage:
    ./venv/bin/python run_scan.py [target]

Default target is an intentionally-vulnerable, publicly-authorized test site.
"""
import os
import sys
import json
import asyncio

from core.harness.supervisor import Supervisor

# Free smoke-test defaults: small fan-out to stay within free-tier daily limits.
HUNTERS = int(os.getenv("KRYX_HUNTERS", "2"))


async def _progress(update: dict):
    event = update.get("event")
    data = update.get("data")
    if event == "status":
        print(f"\n=== STAGE: {data} ===")
    elif event == "hunter_step":
        useful = "★" if data.get("useful") else "·"
        print(f"  [{data['attack_class']:16}] step {data['step']} {useful} "
              f"{data['tool']:14} — {data.get('thought','')[:70]}")
    elif event == "recon":
        print(f"  recon: {json.dumps(data, ensure_ascii=False)[:300]}")
    elif event == "debate":
        icon = {"attacker": "🗡️  АТАКУЮЩИЙ", "defender": "🛡️  ЗАЩИТНИК",
                "judge": "⚖️  СУДЬЯ", "system": "  ·"}.get(data.get("role"), data.get("role"))
        print(f"  [{data.get('finding','')[:30]}] {icon}: {data.get('text','')[:150]}")
    elif event == "findings_raw":
        print(f"\n  raw findings: {len(data)}")
    elif event == "findings_validated":
        print(f"  validated findings: {len(data)}")
    elif event == "chains":
        print(f"  attack chains: {len(data)}")


async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
    print(f"Kryx engine — scanning: {target}  (hunters={HUNTERS}, model={os.getenv('KRYX_MODEL') or os.getenv('HEXOR_MODEL','default')})")

    sup = Supervisor(target, max_hunters=HUNTERS, progress_cb=_progress)
    result = await sup.run()

    print("\n" + "=" * 60)
    print("RESULT SUMMARY")
    print("=" * 60)
    print(f"Target:    {result['target']}")
    print(f"Stats:     {json.dumps(result.get('stats', {}), ensure_ascii=False)}")
    print(f"Vulns:     {len(result.get('vulnerabilities', []))}")
    for v in result.get("vulnerabilities", []):
        print(f"  - [{v.get('severity','?'):8}] {v.get('title', v.get('name','?'))}")
    print("\n--- REPORT (first 1500 chars) ---")
    print((result.get("report") or "")[:1500])

    with open("last_scan_result.json", "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("\nFull result saved -> backend/last_scan_result.json")


if __name__ == "__main__":
    asyncio.run(main())
