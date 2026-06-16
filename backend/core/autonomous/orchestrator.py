"""
Kryx Autonomous Orchestrator — discover targets, dispatch to engines, queue
findings for review.

OSS track (white-box, read-only, legal): discover open-source repos, audit
their source, queue findings for responsible disclosure. The bounty track
(active, black-box) reuses the Supervisor behind the authz gate and is added
with an extra "automated-scanning-allowed" rail.

Findings are persisted to a local queue (autonomous_findings.json) that you
review before acting.
"""
import json
import time
import asyncio
from pathlib import Path

from core.harness.code_auditor import CodeAuditor
from core.autonomous import discovery

STORE = Path(__file__).parent / "autonomous_findings.json"


def load_queue() -> list:
    if STORE.exists():
        try:
            return json.loads(STORE.read_text())
        except Exception:
            return []
    return []


def _save(items: list):
    STORE.write_text(json.dumps(items, ensure_ascii=False, indent=2))


async def run_oss_batch(n: int = 2, query: str | None = None,
                        max_size_kb: int = 8000, progress=None) -> list:
    """Discover OSS repos and audit them (white-box). Smallest repos first to
    keep cost/time bounded. Appends results to the review queue."""
    kwargs = {"n": max(n * 4, 8)}
    if query:
        kwargs["query"] = query
    repos = await discovery.discover_oss_repos(**kwargs)

    # smallest first, skip oversized, take n
    repos = sorted([r for r in repos if 0 < r["size_kb"] <= max_size_kb],
                   key=lambda r: r["size_kb"])[:n]

    queue = load_queue()
    results = []
    for repo in repos:
        if progress:
            await progress(f"auditing {repo['full_name']} ({repo['size_kb']}KB)")
        try:
            audit = await CodeAuditor().run(repo["url"])
            entry = {
                "id": f"oss-{int(time.time())}-{repo['full_name'].replace('/', '_')}",
                "type": "oss-whitebox",
                "target": repo["full_name"],
                "url": repo["url"],
                "stars": repo["stars"],
                "language": repo.get("language"),
                "discovered_at": time.strftime("%Y-%m-%d %H:%M"),
                "stats": audit.get("stats", {}),
                "findings": audit.get("findings", []),
                "status": "needs_review",
            }
            queue.insert(0, entry)
            _save(queue)
            results.append(entry)
        except Exception as e:
            results.append({"target": repo["full_name"], "error": f"{type(e).__name__}: {e}"})
    return results


if __name__ == "__main__":
    async def _main():
        res = await run_oss_batch(n=1, progress=lambda m: asyncio.sleep(0, print(m)))
        for r in res:
            if "error" in r:
                print("ERR", r["target"], r["error"])
            else:
                print(f"{r['target']}: {r['stats'].get('total_findings', 0)} findings")
    asyncio.run(_main())
