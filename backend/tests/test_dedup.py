"""
Finding de-duplication / classification helpers. These guard the low-noise
behavior: collapsing the same vuln on the same endpoint across sources, while
keeping genuinely-distinct findings - including the nuclei keyword-first rule
that stops N .env templates from spamming the report.
"""
from core.harness.supervisor import (
    _vuln_type, _finding_path, _clean_name, _dedupe_findings,
)


# ── _vuln_type ────────────────────────────────────────────────
def test_vuln_type_from_name():
    assert _vuln_type({"name": "SQL Injection @ /x"}) == "sqli"
    assert _vuln_type({"name": "OS Command Injection (RCE) @ /ping"}) == "rce"
    assert _vuln_type({"name": "Server-Side Request Forgery (SSRF)"}) == "ssrf"
    assert _vuln_type({"name": "Отсутствие критических security headers"}) == "headers"


def test_nuclei_known_class_collapses_via_keyword():
    """A nuclei .env template must resolve to the 'secret' class (keyword-first),
    so it collapses with our sensitive_files .env hit instead of staying separate."""
    f = {"name": "Codeigniter - .env File Discovery", "vtype": "nuclei:codeigniter-env"}
    assert _vuln_type(f) == "secret"


def test_nuclei_novel_match_stays_distinct():
    """A nuclei hit with no known-class keyword keeps its template id, so two
    different CVEs on one host don't collapse into each other."""
    f = {"name": "Acme Admin Panel Exposed", "vtype": "nuclei:acme-admin-panel"}
    assert _vuln_type(f) == "nuclei:acme-admin-panel"


# ── _finding_path ─────────────────────────────────────────────
def test_finding_path_from_url():
    assert _finding_path({"url": "https://x.com/api/goto?url=y"}) == "/api/goto"
    assert _finding_path({"url": "https://x.com/"}) == ""        # root == site-level
    assert _finding_path({"url": "https://x.com"}) == ""


def test_finding_path_from_name_picks_longest_token_not_label():
    # must grab /api/account, never the '/BOLA' fragment of 'IDOR/BOLA'
    p = _finding_path({"name": "IDOR / BOLA @ /api/account"})
    assert p == "/api/account"


# ── _clean_name ───────────────────────────────────────────────
def test_clean_name_strips_injected_cjk():
    assert _clean_name("SQL Injection 注入 @ /x").strip() == "SQL Injection  @ /x".strip()
    assert _clean_name("  spaced  ") == "spaced"


# ── _dedupe_findings ──────────────────────────────────────────
def test_dedup_collapses_same_type_same_path_prefers_tool():
    findings = [
        {"name": "SQL Injection @ /x", "url": "https://x.com/x", "source": "llm", "severity": "critical"},
        {"name": "SQL Injection @ /x", "url": "https://x.com/x", "source": "sweep", "severity": "high"},
    ]
    out = _dedupe_findings(findings)
    assert len(out) == 1
    # tool-confirmed (sweep) wins even though the LLM rated it higher severity
    assert out[0]["source"] == "sweep"


def test_dedup_keeps_distinct_types_on_same_path():
    findings = [
        {"name": "SQL Injection @ /x", "url": "https://x.com/x", "source": "sweep", "severity": "high"},
        {"name": "Cross-Site Scripting (XSS) @ /x", "url": "https://x.com/x", "source": "sweep", "severity": "high"},
    ]
    out = _dedupe_findings(findings)
    assert len(out) == 2


def test_dedup_env_templates_collapse_across_paths():
    """The same .env exposure found at different paths (sensitive_files reports
    it site-level, nuclei reports it at /.env) must collapse to one finding."""
    findings = [
        {"name": "Exposed sensitive file", "url": "https://x.com", "source": "sweep", "severity": "high"},
        {"name": "Codeigniter - .env File Discovery", "url": "https://x.com/.env",
         "vtype": "nuclei:codeigniter-env", "source": "sweep", "severity": "high"},
        {"name": "Laravel - Sensitive Information Disclosure", "url": "https://x.com/.env",
         "vtype": "nuclei:laravel-env", "source": "sweep", "severity": "high"},
    ]
    out = _dedupe_findings(findings)
    assert len(out) == 1


def test_dedup_distinct_exposures_stay_separate():
    """Different exposed files on one host (config.json vs .git) are NOT secrets
    by keyword, so their distinct nuclei ids keep them as separate findings."""
    findings = [
        {"name": "Exposed JSON Configuration Files", "url": "https://x.com/config.json",
         "vtype": "nuclei:config-json-exposure-fuzz", "source": "sweep", "severity": "critical"},
        {"name": "Git Configuration - Detect", "url": "https://x.com/.git/config",
         "vtype": "nuclei:git-config", "source": "sweep", "severity": "medium"},
    ]
    out = _dedupe_findings(findings)
    assert len(out) == 2
