import json
import re
from fastapi import APIRouter
from pydantic import BaseModel
from utils.llm import ask
from core.agents.recon import run_recon

router = APIRouter()


class ScanRequest(BaseModel):
    target: str


@router.post("/scan")
async def run_scan(req: ScanRequest):
    recon = await run_recon(req.target)

    result = await ask(
        system=(
            "You are an expert penetration tester. Analyze the recon data and return ONLY valid JSON "
            "with this structure: {\"summary\": string, \"vulnerabilities\": [{\"name\": string, "
            "\"severity\": \"critical|high|medium|low\", \"description\": string, \"recommendation\": string}], "
            "\"report\": string (markdown)}. No extra text, just JSON."
        ),
        prompt=f"Target: {req.target}\nRecon data:\n{json.dumps(recon, indent=2)}\n\nAnalyze and find vulnerabilities.",
    )

    try:
        data = json.loads(result)
    except json.JSONDecodeError:
        match = re.search(r'\{.*\}', result, re.DOTALL)
        data = json.loads(match.group()) if match else {"summary": result, "vulnerabilities": [], "report": result}

    return {"target": req.target, "recon": recon, **data}


@router.get("/health")
def health():
    return {"status": "ok"}
