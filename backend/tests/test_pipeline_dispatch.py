"""
The unified SaaS pipeline must dispatch to the REAL engine for each target
type - Supervisor for live web targets, CodeAuditor for source/repos - instead
of the old half-built static stub. These tests pin that routing without running
a real scan (the engines are faked).
"""
import pytest

import core.harness.supervisor as sup_mod
import core.harness.code_auditor as ca_mod
from core.harness.supervisor_v2 import run_pipeline


class _FakeSupervisor:
    last_target = None

    def __init__(self, target, progress_cb=None):
        _FakeSupervisor.last_target = target

    async def run(self):
        return {"vulnerabilities": [{"name": "SQLi", "severity": "high"}],
                "summary": "live-summary", "report": "live-report", "stats": {"n": 1}}


class _FakeCodeAuditor:
    last_source = None

    def __init__(self, progress_cb=None):
        pass

    async def run(self, source, github_token=None):
        _FakeCodeAuditor.last_source = source
        return {"findings": [{"name": "Hardcoded secret", "severity": "medium"}],
                "summary": "static-summary", "report": "static-report", "stats": {"n": 1}}


@pytest.fixture(autouse=True)
def fake_engines(monkeypatch):
    monkeypatch.setattr(sup_mod, "Supervisor", _FakeSupervisor)
    monkeypatch.setattr(ca_mod, "CodeAuditor", _FakeCodeAuditor)
    yield


def test_web_target_uses_supervisor():
    import asyncio
    res = asyncio.run(run_pipeline("https://example.com", "web"))
    assert _FakeSupervisor.last_target == "https://example.com"
    assert res.summary == "live-summary"
    assert res.static_findings and res.static_findings[0]["name"] == "SQLi"


def test_repo_target_uses_code_auditor():
    import asyncio
    res = asyncio.run(run_pipeline("/path/to/repo", "repo"))
    assert _FakeCodeAuditor.last_source == "/path/to/repo"
    assert res.summary == "static-summary"
    assert res.static_findings[0]["name"] == "Hardcoded secret"


def test_no_db_session_skips_persist():
    """With no scan_id/db_session the pipeline just runs the engine and returns."""
    import asyncio
    res = asyncio.run(run_pipeline("https://example.com", "web", scan_id=None, db_session=None))
    assert res.finished_at is not None
