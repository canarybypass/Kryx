"""
Bug Bounty Writeups Scraper
Собирает writeups из публичных источников
"""
import asyncio
import httpx
from bs4 import BeautifulSoup
import json
from pathlib import Path

BASE = Path(__file__).parent.parent
RAW = BASE / "raw"
RAW.mkdir(exist_ok=True)


async def fetch_medium_writeups(limit: int = 100) -> list:
    """Scrape bug bounty writeups from Medium"""
    writeups = []
    
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        tags = ["bug-bounty", "cybersecurity", "penetration-testing", "web-security"]
        
        for tag in tags:
            try:
                # Medium RSS feed
                url = f"https://medium.com/feed/tag/{tag}"
                r = await client.get(url)
                
                if r.status_code == 200:
                    import feedparser
                    feed = feedparser.parse(r.text)
                    
                    for entry in feed.entries[:25]:
                        if any(kw in entry.title.lower() for kw in ["vulnerability", "exploit", "bug", "xss", "sqli", "rce", "ssrf"]):
                            writeups.append({
                                "title": entry.title,
                                "link": entry.link,
                                "summary": entry.get("summary", "")[:1000],
                                "published": entry.get("published", ""),
                                "author": entry.get("author", ""),
                                "source": f"Medium:{tag}"
                            })
                
                await asyncio.sleep(2)
                
            except Exception as e:
                print(f"  Error fetching {tag}: {e}")
    
    # Deduplicate
    seen = set()
    unique = []
    for w in writeups:
        if w["link"] not in seen:
            seen.add(w["link"])
            unique.append(w)
    
    return unique[:limit]


async def fetch_pentesterlab_writeups() -> list:
    """Fetch PentesterLab exercises (public info only)"""
    writeups = []
    
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.get("https://pentesterlab.com/exercises")
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                
                for exercise in soup.select(".exercise-item")[:50]:
                    title_elem = exercise.select_one(".exercise-title")
                    desc_elem = exercise.select_one(".exercise-description")
                    
                    if title_elem:
                        writeups.append({
                            "title": title_elem.get_text(strip=True),
                            "description": desc_elem.get_text(strip=True) if desc_elem else "",
                            "link": "https://pentesterlab.com" + title_elem.get("href", ""),
                            "source": "PentesterLab"
                        })
        except Exception as e:
            print(f"  PentesterLab error: {e}")
    
    return writeups


async def fetch_portswigger_labs() -> list:
    """Fetch PortSwigger Web Security Academy labs"""
    labs = []
    
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.get("https://portswigger.net/web-security/all-labs")
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                
                for lab in soup.select(".widgetcontainer-lab-link")[:100]:
                    title = lab.get_text(strip=True)
                    link = lab.get("href", "")
                    
                    if link:
                        labs.append({
                            "title": title,
                            "link": "https://portswigger.net" + link if link.startswith("/") else link,
                            "source": "PortSwigger"
                        })
        except Exception as e:
            print(f"  PortSwigger error: {e}")
    
    return labs


async def main():
    print("Fetching bug bounty writeups...")
    
    print("\n[1/3] Medium writeups...")
    medium = await fetch_medium_writeups(100)
    print(f"  ✓ {len(medium)} writeups")
    
    print("\n[2/3] PentesterLab exercises...")
    pentester = await fetch_pentesterlab_writeups()
    print(f"  ✓ {len(pentester)} exercises")
    
    print("\n[3/3] PortSwigger labs...")
    portswigger = await fetch_portswigger_labs()
    print(f"  ✓ {len(portswigger)} labs")
    
    all_writeups = medium + pentester + portswigger
    
    # Save
    with open(RAW / "writeups_raw.json", "w") as f:
        json.dump(all_writeups, f, indent=2, ensure_ascii=False)
    
    print(f"\nTotal: {len(all_writeups)} writeups saved")


if __name__ == "__main__":
    asyncio.run(main())
