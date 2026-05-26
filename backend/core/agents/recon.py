import httpx
from utils.llm import ask


class ReconAgent:
    async def run(self, target: str) -> dict:
        # Basic passive recon: DNS, HTTP headers, tech detection
        info = await self._fetch_headers(target)
        summary = await ask(
            system="You are a cybersecurity recon expert. Analyze the target info and identify technologies, server software, and potential attack surface.",
            prompt=f"Target: {target}\nHTTP Headers: {info}\n\nProvide a structured recon summary.",
        )
        return {"target": target, "headers": info, "summary": summary}

    async def _fetch_headers(self, target: str) -> dict:
        url = target if target.startswith("http") else f"https://{target}"
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                r = await client.head(url)
                return dict(r.headers)
        except Exception as e:
            return {"error": str(e)}
