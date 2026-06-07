from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.harness.supervisor import Supervisor
from core.harness.code_auditor import CodeAuditor
from db import Scan, AuditResult, get_db, SessionLocal
from auth import (
    RegisterRequest, LoginRequest, TokenResponse, UserOut,
    CurrentUser, register, login, SECRET_KEY, ALGORITHM,
)

router = APIRouter()
DB = Annotated[AsyncSession, Depends(get_db)]


# ── Auth ───────────────────────────────────────────────────

@router.post("/auth/register", response_model=TokenResponse)
async def route_register(req: RegisterRequest, db: DB):
    return await register(req, db)


@router.post("/auth/login", response_model=TokenResponse)
async def route_login(req: LoginRequest, db: DB):
    return await login(req, db)


@router.get("/auth/me", response_model=UserOut)
async def route_me(user: CurrentUser):
    return user


# ── Scans history ──────────────────────────────────────────

@router.get("/scans")
async def list_scans(user: CurrentUser, db: DB):
    rows = await db.scalars(
        select(Scan).where(Scan.user_id == user.id)
        .order_by(Scan.created_at.desc()).limit(50)
    )
    return [
        {"id": s.id, "target": s.target, "status": s.status,
         "summary": s.summary, "stats": s.stats, "created_at": s.created_at}
        for s in rows
    ]




# ── V2 Scans (New 6-stage pipeline) ────────────────────────

class ScanRequestV2(BaseModel):
    target: str
    target_type: str = "repo"  # web|repo|binary|source


@router.post("/v2/scans")
async def create_scan_v2(req: ScanRequestV2, user: CurrentUser, db: DB):
    """
    Create new scan using v2 pipeline (6 stages).
    
    Returns scan ID immediately, runs in background.
    Use WebSocket /v2/scans/{id}/live for progress.
    """
    from core.harness.supervisor_v2 import SupervisorV2
    from db import Scan, ScanStatus
    
    # Check org scan limit
    org = user.organization
    if org.monthly_scans_used >= org.monthly_scan_limit:
        raise HTTPException(403, "Monthly scan limit reached")
    
    # Create scan record
    scan = Scan(
        organization_id=org.id,
        user_id=user.id,
        target=req.target,
        target_type=req.target_type,
        status=ScanStatus.QUEUED
    )
    db.add(scan)
    
    # Increment usage
    org.monthly_scans_used += 1
    
    await db.commit()
    await db.refresh(scan)
    
    # Start pipeline in background
    import asyncio
    asyncio.create_task(_run_scan_v2(scan.id, req.target, req.target_type))
    
    return {
        "scan_id": scan.id,
        "status": "queued",
        "message": "Scan started. Connect to WebSocket for live updates."
    }


async def _run_scan_v2(scan_id: int, target: str, target_type: str):
    """Background task to run scan pipeline"""
    from core.harness.supervisor_v2 import run_pipeline
    
    async with SessionLocal() as session:
        try:
            # Update to running
            scan = await session.get(Scan, scan_id)
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            await session.commit()
            
            # Run pipeline
            result = await run_pipeline(target, target_type, scan_id, session)
            
            print(f"[Scan {scan_id}] Completed: {len(result.static_findings)} findings")
        
        except Exception as e:
            print(f"[Scan {scan_id}] Failed: {e}")
            scan = await session.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.FAILED
                scan.summary = f"Error: {str(e)}"
                await session.commit()


@router.get("/v2/scans/{scan_id}")
async def get_scan_v2(scan_id: int, user: CurrentUser, db: DB):
    """Get scan details including all findings"""
    from sqlalchemy import select
    from db import Vulnerability
    
    scan = await db.get(Scan, scan_id)
    if not scan or scan.organization_id != user.organization_id:
        raise HTTPException(404, "Scan not found")
    
    # Get vulnerabilities
    vulns_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    )
    vulns = vulns_result.scalars().all()
    
    return {
        "id": scan.id,
        "target": scan.target,
        "target_type": scan.target_type,
        "status": scan.status,
        "summary": scan.summary,
        "stats": scan.stats,
        "vulnerabilities": [
            {
                "id": v.id,
                "type": v.vuln_type,
                "severity": v.severity,
                "name": v.name,
                "description": v.description,
                "location": v.location,
                "cwe_id": v.cwe_id,
                "verified": v.verified,
                "exploitability_score": v.exploitability_score
            }
            for v in vulns
        ],
        "pipeline_progress": {
            "static_analysis": scan.static_analysis_done,
            "fuzzing": scan.fuzzing_done,
            "variant_hunt": scan.variant_hunt_done,
            "exploit_build": scan.exploit_build_done,
            "verification": scan.verification_done
        },
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at
    }


@router.websocket("/v2/scans/{scan_id}/live")
async def scan_live_v2(websocket: WebSocket, scan_id: int):
    """
    Live progress updates for scan.
    
    Events:
    - pipeline_started
    - stage_started {stage}
    - stage_completed {stage, findings_count}
    - stage_failed {stage, error}
    - pipeline_completed
    """
    await websocket.accept()
    
    # TODO: Implement WebSocket progress streaming
    # For now, just send initial status
    
    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            await websocket.send_json({"error": "Scan not found"})
            await websocket.close()
            return
        
        await websocket.send_json({
            "event": "connected",
            "data": {"scan_id": scan_id, "status": scan.status}
        })
        
        # Keep connection open and send updates
        try:
            while True:
                # Poll for updates
                await asyncio.sleep(2)
                
                scan = await session.get(Scan, scan_id)
                await websocket.send_json({
                    "event": "status_update",
                    "data": {
                        "status": scan.status,
                        "static_analysis": scan.static_analysis_done,
                        "fuzzing": scan.fuzzing_done,
                        "variant_hunt": scan.variant_hunt_done,
                        "exploit_build": scan.exploit_build_done,
                        "verification": scan.verification_done
                    }
                })
                
                if scan.status in [ScanStatus.COMPLETED, ScanStatus.FAILED]:
                    break
        
        except WebSocketDisconnect:
            pass
        finally:
            await websocket.close()
@router.get("/scans/{scan_id}")
async def get_scan(scan_id: int, user: CurrentUser, db: DB):
    scan = await db.get(Scan, scan_id)
    if not scan or scan.user_id != user.id:
        raise HTTPException(404, "Scan not found")
    return scan


# ── Scan (REST) ────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    max_hunters: int = 8


@router.post("/scan")
async def run_scan(req: ScanRequest, user: CurrentUser, db: DB):
    scan = Scan(user_id=user.id, target=req.target, status="running")
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    try:
        result = await Supervisor(req.target, max_hunters=req.max_hunters).run()
        scan.status = "done"
        scan.summary = result.get("summary")
        scan.report = result.get("report")
        scan.findings = result.get("vulnerabilities")
        scan.stats = result.get("stats")
        scan.finished_at = datetime.utcnow()
    except Exception as e:
        scan.status = "error"
        scan.summary = str(e)
        result = {"error": str(e)}

    await db.commit()
    return result


# ── Scan (WebSocket) ───────────────────────────────────────

@router.websocket("/ws/scan")
async def ws_scan(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        target = data.get("target", "")
        max_hunters = data.get("max_hunters", 8)
        token = data.get("token")

        if not target:
            await websocket.send_json({"event": "error", "data": "No target provided"})
            return

        user_id = _user_id_from_token(token)

        scan_id = None
        if user_id:
            async with SessionLocal() as db:
                scan = Scan(user_id=user_id, target=target, status="running")
                db.add(scan)
                await db.commit()
                await db.refresh(scan)
                scan_id = scan.id

        async def cb(msg):
            try: await websocket.send_json(msg)
            except Exception: pass

        result = await Supervisor(target, max_hunters=max_hunters, progress_cb=cb).run()
        await websocket.send_json({"event": "complete", "data": result})

        if scan_id:
            async with SessionLocal() as db:
                scan = await db.get(Scan, scan_id)
                if scan:
                    scan.status = "done"
                    scan.summary = result.get("summary")
                    scan.report = result.get("report")
                    scan.findings = result.get("vulnerabilities")
                    scan.stats = result.get("stats")
                    scan.finished_at = datetime.utcnow()
                    await db.commit()

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try: await websocket.send_json({"event": "error", "data": str(e)})
        except Exception: pass


# ── Audit history ──────────────────────────────────────────

@router.get("/audits")
async def list_audits(user: CurrentUser, db: DB):
    rows = await db.scalars(
        select(AuditResult).where(AuditResult.user_id == user.id)
        .order_by(AuditResult.created_at.desc()).limit(50)
    )
    return [
        {"id": a.id, "source": a.source, "status": a.status,
         "files_analyzed": a.files_analyzed, "stats": a.stats, "created_at": a.created_at}
        for a in rows
    ]


# ── Audit (REST) ───────────────────────────────────────────

class AuditRequest(BaseModel):
    source: str
    github_token: str | None = None


@router.post("/audit")
async def run_audit(req: AuditRequest, user: CurrentUser, db: DB):
    record = AuditResult(user_id=user.id, source=req.source, status="running")
    db.add(record)
    await db.commit()
    await db.refresh(record)

    try:
        result = await CodeAuditor().run(req.source, req.github_token)
        record.status = "done"
        record.files_analyzed = result.get("files_analyzed", 0)
        record.findings = result.get("findings")
        record.variants = result.get("variants")
        record.report = result.get("report")
        record.stats = result.get("stats")
        record.finished_at = datetime.utcnow()
    except Exception as e:
        record.status = "error"
        record.report = str(e)
        result = {"error": str(e)}

    await db.commit()
    return result


# ── Audit (WebSocket) ──────────────────────────────────────

@router.websocket("/ws/audit")
async def ws_audit(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        source = data.get("source", "")
        github_token = data.get("github_token")
        token = data.get("token")

        if not source:
            await websocket.send_json({"event": "error", "data": "No source provided"})
            return

        user_id = _user_id_from_token(token)

        record_id = None
        if user_id:
            async with SessionLocal() as db:
                record = AuditResult(user_id=user_id, source=source, status="running")
                db.add(record)
                await db.commit()
                await db.refresh(record)
                record_id = record.id

        async def cb(msg):
            try: await websocket.send_json(msg)
            except Exception: pass

        result = await CodeAuditor(progress_cb=cb).run(source, github_token)
        await websocket.send_json({"event": "complete", "data": result})

        if record_id:
            async with SessionLocal() as db:
                record = await db.get(AuditResult, record_id)
                if record:
                    record.status = "done"
                    record.files_analyzed = result.get("files_analyzed", 0)
                    record.findings = result.get("findings")
                    record.variants = result.get("variants")
                    record.report = result.get("report")
                    record.stats = result.get("stats")
                    record.finished_at = datetime.utcnow()
                    await db.commit()

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try: await websocket.send_json({"event": "error", "data": str(e)})
        except Exception: pass


# ── Benchmark ──────────────────────────────────────────────

class BenchmarkRequest(BaseModel):
    target_names: list[str] | None = None
    difficulty: str | None = None
    max_hunters: int = 8


@router.post("/benchmark")
async def run_benchmark_endpoint(req: BenchmarkRequest, user: CurrentUser):
    from benchmark.runner import run_benchmark
    return await run_benchmark(
        target_names=req.target_names,
        difficulty=req.difficulty,
        max_hunters=req.max_hunters,
    )


# ── Health ─────────────────────────────────────────────────

@router.get("/health")
def health():
    return {"status": "ok", "version": "0.4.0"}


# ── Helpers ────────────────────────────────────────────────

def _user_id_from_token(token: str | None) -> int | None:
    if not token:
        return None
    try:
        from jose import jwt
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return int(payload["sub"])
    except Exception:
        return None
