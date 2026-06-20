<div align="center">

# ⚡ Kryx

**Autonomous AI offensive-security agent.**
Finds vulnerabilities, **proves** each one by execution, chains them to real impact, and writes the fix -
across live web apps and source code. Reasoning where scanners are blind; low-noise where scanners are loud.

</div>

---

## What it does

### 🎯 Black-box - live targets
A deterministic pipeline maps the real attack surface and confirms every vuln with a tool, so findings are proven, not guessed:

```
recon → crawl (JS-aware) → sweep (every detector on every endpoint) → business-logic
      → LLM hunt → adversarial debate (verify) → attack-chains → report
```

- **Tool-confirmed classes:** SQLi · XSS (reflected/stored/DOM) · command injection (RCE) · SSTI · path-traversal/LFI · IDOR/BOLA · SSRF (out-of-band) · open redirect · CORS · exposed secrets/configs · **JSON-body API injection** · known CVEs & exposures (nuclei).
- **Business-logic flaws** scanners can't find: negative price/quantity, price & role tampering, broken object-level access - confirmed by the server's own response.
- **Visible adversarial debate:** an attacker argues a finding is real, a defender attacks it, a judge rules - before it reaches the report.
- Every finding ships a **proof-of-concept + a ready-to-apply fix**.

### 🔬 White-box - source code
Point it at a repo or path: taint analysis by reasoning, an adversarial validation pass to kill false positives, and ready-to-apply fix code.

### 🤖 Autonomous mode
Discovers authorized targets (bug-bounty scopes, OSS repos) and audits them - behind a hard **authorization gate** that refuses any host it isn't allowed to test.

---

## Repository layout

```
kryx/
├── backend/                 # the engine + SaaS API
│   ├── core/
│   │   ├── harness/         # pipeline: crawler · sweep · hunter · debate · chains · reporter · code_auditor
│   │   ├── tools/           # deterministic detectors (scanner.py: sqli, xss, cmdi, ssrf, nuclei, …)
│   │   ├── agents/          # LLM prompts
│   │   └── autonomous/      # authorization gate + target discovery
│   ├── api/                 # FastAPI SaaS routes (auth · scans · history)
│   ├── billing/             # Stripe integration
│   ├── integrations/        # GitHub / GitLab webhooks
│   ├── testbed/             # intentionally-vulnerable app for local testing
│   ├── tests/               # pytest suite (authz gate · dedup · pipeline dispatch)
│   ├── webapp.py            # personal web console (scan from a browser)
│   ├── run_scan.py          # CLI runner
│   └── main.py              # SaaS API entrypoint
├── frontend/                # React product UI
├── landing/                 # marketing landing page (static, self-contained)
├── cli/                     # CLI client
└── docs/                    # architecture · database · integrations · billing
```

---

## Quick start

```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
playwright install chromium          # for the JS-aware crawl / DOM XSS

cp .env.example .env                 # set KRYX_MODEL + OPENROUTER_API_KEY

# scan a target (authorized only)
python run_scan.py https://your-authorized-target

# …or run scans from a browser (set a strong key — the console refuses to start without one)
KRYX_WEB_KEY=$(python -c 'import secrets; print(secrets.token_urlsafe(24))') \
  ./venv/bin/uvicorn webapp:app --host 0.0.0.0 --port 8000
```

For known-CVE coverage, install [nuclei](https://github.com/projectdiscovery/nuclei) and make sure it's on `PATH`.

### Tests

```bash
cd backend && ./venv/bin/python -m pytest tests/ -q
```

---

## Configuration (`backend/.env`)

| Var | Purpose |
|-----|---------|
| `OPENROUTER_API_KEY` | LLM provider key |
| `KRYX_MODEL` | reasoning model (e.g. `openrouter/anthropic/claude-opus-4.8`) |
| `KRYX_HUNTERS` | parallel LLM hunters (default 8) |
| `KRYX_WEB_KEY` | access key for the web console (required) |
| `KRYX_NUCLEI` | set `0` to skip the nuclei stage |

---

## Authorization

Kryx **only** actively scans hosts that are local/lab, listed in
`backend/core/autonomous/authorized_scopes.txt`, or in a fetched bug-bounty scope
whose program permits automated testing. Everything else is refused. The gate is
covered by tests - **only test what you're authorized to test.**

---

## Docs

- [Architecture](docs/ARCHITECTURE.md)
- [Database](docs/DATABASE.md)
- [Integrations](docs/INTEGRATIONS.md)
- [Billing](docs/BILLING.md)

---

© Kryx - proprietary. All rights reserved. See [LICENSE](LICENSE).
