from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from core.harness.supervisor import Supervisor
import asyncio
import json

router = APIRouter()


class ScanRequest(BaseModel):
    target: str
    max_hunters: int = 8


@router.post("/scan")
async def run_scan(req: ScanRequest):
    supervisor = Supervisor(req.target, max_hunters=req.max_hunters)
    return await supervisor.run()


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


@router.get("/health")
def health():
    return {"status": "ok", "version": "0.2.0"}