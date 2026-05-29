"""
HackerOne Public Reports Fetcher
Собирает публичные disclosed reports с HackerOne
"""
import asyncio
import httpx
import json
from pathlib import Path

BASE = Path(__file__).parent.parent
RAW = BASE / "raw"
RAW.mkdir(exist_ok=True)


async def fetch_hackerone_reports(limit: int = 500) -> list:
    """Fetch public disclosed reports from HackerOne"""
    reports = []
    
    async with httpx.AsyncClient(timeout=30) as client:
        page = 1
        while len(reports) < limit:
            try:
                # HackerOne GraphQL API (public)
                query = """
                query {
                  reports(first: 100, disclosed: true, orderBy: {field: disclosed_at, direction: DESC}) {
                    edges {
                      node {
                        id
                        title
                        severity_rating
                        weakness {
                          name
                        }
                        bounty_amount
                        disclosed_at
                        summary
                        vulnerability_information
                      }
                    }
                  }
                }
                """
                
                # Fallback: scrape hacktivity page
                r = await client.get(
                    f"https://hackerone.com/hacktivity.json",
                    params={"page": page, "filter": "type:public"},
                    headers={"Accept": "application/json"}
                )
                
                if r.status_code != 200:
                    break
                
                data = r.json()
                items = data.get("reports", [])
                
                if not items:
                    break
                
                for item in items:
                    report = item.get("report", item)
                    reports.append({
                        "id": report.get("id", ""),
                        "title": report.get("title", ""),
                        "severity": report.get("severity_rating", ""),
                        "weakness": report.get("weakness", {}).get("name", ""),
                        "bounty": report.get("bounty_amount", ""),
                        "disclosed_at": report.get("disclosed_at", ""),
                        "summary": str(report.get("vulnerability_information", ""))[:2000],
                        "program": report.get("team", {}).get("name", ""),
                        "source": "HackerOne"
                    })
                
                print(f"  Fetched {len(reports)} reports...")
                page += 1
                await asyncio.sleep(2)
                
            except Exception as e:
                print(f"  Error on page {page}: {e}")
                break
    
    # Save raw
    with open(RAW / "hackerone_raw.json", "w") as f:
        json.dump(reports, f, indent=2, ensure_ascii=False)
    
    return reports


async def main():
    print("Fetching HackerOne reports...")
    reports = await fetch_hackerone_reports(500)
    print(f"Total: {len(reports)} reports")
    
    # Stats
    severities = {}
    for r in reports:
        sev = r.get("severity", "none")
        severities[sev] = severities.get(sev, 0) + 1
    
    print("\nSeverity distribution:")
    for sev, count in sorted(severities.items(), key=lambda x: -x[1]):
        print(f"  {sev}: {count}")


if __name__ == "__main__":
    asyncio.run(main())
