from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from core.harness.supervisor import Supervisor
from core.harness.code_auditor import CodeAuditor
import json

router = APIRouter()


class ScanRequest(BaseModel):
    target: str
    max_hunters: int = 8


class AuditRequest(BaseModel):
    source: str          # GitHub URL, local path, or archive path
    github_token: str | None = None


@router.post("/scan")
async def run_scan(req: ScanRequest):
    supervisor = Supervisor(req.target, max_hunters=req.max_hunters)
    return await supervisor.run()


@router.post("/audit")
async def run_audit(req: AuditRequest):
    auditor = CodeAuditor()
    return await auditor.run(req.source, req.github_token)


@router.websocket("/ws/scan")
async def ws_scan(websocket: WebSocket):
    await websocket.accept()

    try:
        data = await websocket.receive_json()
        target = data.get("target", "")
        max_hunters = data.get("max_hunters", 8)

        if not target:
            await websocket.send_json({"event": "error", "data": "No target provided"})
            await websocket.close()
            return

        async def progress_cb(msg: dict):
            try:
                await websocket.send_json(msg)
            except Exception:
                pass

        supervisor = Supervisor(target, max_hunters=max_hunters, progress_cb=progress_cb)
        result = await supervisor.run()

        await websocket.send_json({"event": "complete", "data": result})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"event": "error", "data": str(e)})
        except Exception:
            pass


@router.websocket("/ws/audit")
async def ws_audit(websocket: WebSocket):
    await websocket.accept()

    try:
        data = await websocket.receive_json()
        source = data.get("source", "")
        github_token = data.get("github_token")

        if not source:
            await websocket.send_json({"event": "error", "data": "No source provided"})
            await websocket.close()
            return

        async def progress_cb(msg: dict):
            try:
                await websocket.send_json(msg)
            except Exception:
                pass

        auditor = CodeAuditor(progress_cb=progress_cb)
        result = await auditor.run(source, github_token)

        await websocket.send_json({"event": "complete", "data": result})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"event": "error", "data": str(e)})
        except Exception:
            pass


@router.get("/health")
def health():
    return {"status": "ok", "version": "0.3.0"}