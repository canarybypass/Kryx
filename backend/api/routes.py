from fastapi import APIRouter
from pydantic import BaseModel
from core.agents.orchestrator import run_agent

router = APIRouter()


class ScanRequest(BaseModel):
    target: str
    max_steps: int = 10


@router.post("/scan")
async def run_scan(req: ScanRequest):
    return await run_agent(req.target, req.max_steps)


@router.get("/health")
def health():
    return {"status": "ok"}
