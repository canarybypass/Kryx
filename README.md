# Kryx

**AI offensive-security agent.** Finds vulnerabilities, proves them, and writes the fix — across live web apps and source code. Reasoning where scanners are blind; low-noise where scanners are loud.

---

## What it does

**Black-box (live targets)** — a deterministic pipeline that maps the real attack surface and confirms vulns with tools:

```
recon → crawl (JS-aware) → sweep (every detector on every endpoint)
      → business-logic → LLM hunt → validate → attack-chains → report
```

- **8 vuln classes, tool-confirmed:** SQLi, XSS (reflected/stored/DOM), command injection (RCE), SSTI, path traversal/LFI, IDOR/BOLA, SSRF, exposed config/secrets.
- **Business-logic flaws** scanners can't find: negative price/quantity, price & role tampering, missing validation — confirmed by the server's own response.
- Every finding ships **PoC (proof) + remediation (fix)**.

**White-box (source code)** — point it at a repo: taint analysis by reasoning, an adversarial validation pass to kill false positives, and ready-to-apply fix code.

**Autonomous mode** — discovers authorized targets (bug-bounty scopes, OSS repos) and audits them, behind a hard **authorization gate** (never touches a host it isn't allowed to test).

---

## Quick start

```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
playwright install chromium          # for JS-aware crawl / DOM XSS
cp .env.example .env                 # set KRYX_MODEL + OPENROUTER_API_KEY

# scan a target (authorized only)
python run_scan.py https://your-authorized-target

# or the web console (run scans from a browser/phone)
KRYX_WEB_KEY=yourkey uvicorn webapp:app --host 0.0.0.0 --port 8000
```

## Configuration (`backend/.env`)

| Var | Purpose |
|-----|---------|
| `KRYX_MODEL` | LLM (e.g. `openrouter/deepseek/deepseek-chat-v3-0324`) |
| `OPENROUTER_API_KEY` | provider key |
| `KRYX_HUNTERS` | parallel LLM hunters (default 8) |
| `KRYX_WEB_KEY` | access key for the web console |

## Authorization

Kryx **only** actively scans hosts that are local/lab, listed in
`backend/core/autonomous/authorized_scopes.txt`, or in a fetched bug-bounty
scope. Everything else is refused. Only test what you're authorized to test.
