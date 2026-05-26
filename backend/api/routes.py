from fastapi import APIRouter
from pydantic import BaseModel
from utils.llm import ask
import httpx
import json

router = APIRouter()


class ScanRequest(BaseModel):
    target: str


@router.post("/scan")
async def run_scan(req: ScanRequest):
    # Fetch basic info about target
    headers_info = await _fetch_headers(req.target)

    result = await ask(
        system=(
            "You are an expert penetration tester. Analyze the target and return ONLY valid JSON "
            "with this structure: {\"summary\": string, \"vulnerabilities\": [{\"name\": string, "
            "\"severity\": \"critical|high|medium|low\", \"description\": string, \"recommendation\": string}], "
            "\"report\": string (markdown)}. No extra text, just JSON."
        ),
        prompt=f"Target: {req.target}\nHTTP Headers: {json.dumps(headers_info)}\n\nAnalyze and find vulnerabilities.",
    )

    try:
        data = json.loads(result)
    except json.JSONDecodeError:
        # Try to extract JSON from response
        import re
        match = re.search(r'\{.*\}', result, re.DOTALL)
        data = json.loads(match.group()) if match else {"summary": result, "vulnerabilities": [], "report": result}

    return {"target": req.target, **data}


async def _fetch_headers(target: str) -> dict:
    url = target if target.startswith("http") else f"https://{target}"
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            r = await client.head(url)
            return dict(r.headers)
    except Exception as e:
        return {"error": str(e)}


@router.get("/health")
def health():
    return {"status": "ok"}
