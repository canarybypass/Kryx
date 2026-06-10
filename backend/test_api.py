"""
Simple backend test - check if FastAPI starts
"""
from fastapi import FastAPI
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from typing import List, Optional
from pydantic import BaseModel
import uuid
import time
import os

app = FastAPI(title="Vulnyx API")

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# In-memory storage for demo
scans_db = {}

@app.get("/", response_class=HTMLResponse)
async def root():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r") as f:
            return f.read()
    return "<h1>Vulnyx API</h1><p>Backend is running. <a href='/docs'>API Docs</a></p>"

@app.get("/health")
async def health():
    return {"status": "ok", "service": "Vulnyx"}

@app.get("/api/v2/test")
async def test():
    return {
        "message": "Vulnyx API v2.0",
        "features": [
            "Static Analysis",
            "Variant Hunter",
            "Exploit Builder",
            "Sandbox Verification"
        ]
    }

# Scan models
class ScanCreate(BaseModel):
    target: str
    target_type: str = "repo"

class ScanResponse(BaseModel):
    id: int
    target: str
    target_type: str
    status: str
    created_at: str
    pipeline_progress: dict
    stats: dict
    vulnerabilities: List[dict]

@app.post("/api/v2/scans", response_model=ScanResponse)
async def create_scan(scan: ScanCreate):
    scan_id = len(scans_db) + 1
    scans_db[scan_id] = {
        "id": scan_id,
        "target": scan.target,
        "target_type": scan.target_type,
        "status": "completed",
        "created_at": "2026-06-09T12:00:00",
        "pipeline_progress": {
            "static_analysis": True,
            "fuzzing": False,
            "variant_hunt": True,
            "exploit_build": True,
            "verification": True
        },
        "stats": {
            "total_findings": 3,
            "by_severity": {
                "critical": 1,
                "high": 1,
                "medium": 1,
                "low": 0
            }
        },
        "vulnerabilities": [
            {
                "id": 1,
                "name": "SQL Injection",
                "type": "injection",
                "severity": "critical",
                "location": "/app/routes.py:42",
                "verified": True
            },
            {
                "id": 2,
                "name": "XSS Reflected",
                "type": "xss",
                "severity": "high", 
                "location": "/app/templates/login.html:15",
                "verified": True
            },
            {
                "id": 3,
                "name": "Insecure Direct Object Reference",
                "type": "idor",
                "severity": "medium",
                "location": "/app/api/users.py:88",
                "verified": False
            }
        ],
        "summary": "Found 3 vulnerabilities in target"
    }
    return scans_db[scan_id]

@app.get("/api/v2/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int):
    if scan_id not in scans_db:
        # Return demo scan
        return scans_db.get(1, {"error": "Scan not found"})
    return scans_db[scan_id]

@app.get("/api/scans")
async def list_scans(limit: int = 20):
    return list(scans_db.values())[:limit]

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Vulnyx API test server...")
    print("🌐 Web UI: http://localhost:8000")
    print("📚 API Docs: http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)
