"""
Security Papers Fetcher (arXiv)
Собирает research papers по security из arXiv
"""
import asyncio
import feedparser
import json
from pathlib import Path

BASE = Path(__file__).parent.parent
RAW = BASE / "raw"
RAW.mkdir(exist_ok=True)


async def fetch_arxiv_papers(max_results: int = 500) -> list:
    """Fetch security papers from arXiv"""
    papers = []
    
    categories = ["cs.CR"]  # Cryptography and Security
    keywords = [
        "vulnerability", "exploit", "penetration testing",
        "security analysis", "malware", "intrusion detection",
        "fuzzing", "symbolic execution", "program analysis"
    ]
    
    for keyword in keywords:
        print(f"  Searching: {keyword}")
        
        import urllib.parse
        query = f"cat:cs.CR AND all:{keyword}"
        encoded_query = urllib.parse.quote(query)
        url = f"http://export.arxiv.org/api/query?search_query={encoded_query}&sortBy=submittedDate&max_results=100"
        
        feed = feedparser.parse(url)
        
        for entry in feed.entries:
            papers.append({
                "id": entry.id.split("/")[-1],
                "title": entry.title,
                "summary": entry.summary[:1000],
                "authors": [a.name for a in entry.authors],
                "published": entry.published,
                "link": entry.link,
                "categories": [t.term for t in entry.tags],
                "source": "arXiv"
            })
        
        await asyncio.sleep(3)  # Rate limit
        
        if len(papers) >= max_results:
            break
    
    # Deduplicate by ID
    seen = set()
    unique_papers = []
    for p in papers:
        if p["id"] not in seen:
            seen.add(p["id"])
            unique_papers.append(p)
    
    # Save
    with open(RAW / "arxiv_papers.json", "w") as f:
        json.dump(unique_papers, f, indent=2, ensure_ascii=False)
    
    return unique_papers


async def main():
    print("Fetching arXiv security papers...")
    papers = await fetch_arxiv_papers(500)
    print(f"Total: {len(papers)} papers")


if __name__ == "__main__":
    asyncio.run(main())
