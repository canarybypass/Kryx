# Hexor

AI-powered penetration testing platform. Multi-agent harness with real tool integration.

## Architecture

5-stage multi-agent harness:
1. **Recon** — Attack surface mapping (DNS, WHOIS, HTTP, subdomains)
2. **Hunt** — 8 parallel hunter agents (injection, XSS, auth, config, CORS, network, info, CVE)
3. **Validate** — Adversarial review: independent agent disproves false findings
4. **Chain Builder** — Constructs APT-level attack chains
5. **Reporter** — Professional markdown pentest report in Russian

## Integrated Tools

nmap, nuclei, ffuf, sqlmap, subfinder, testssl.sh, whatweb, NVD API, crt.sh

## Setup

```bash
# Backend
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edit with your API keys
python main.py         # port 8000

# Frontend
cd frontend
npm install && npm start  # port 3000
```

## API

- `POST /api/scan` — Start a scan
- `WebSocket /api/ws/scan` — Live progress streaming
- `GET /api/health` — Health check

## Roadmap

- [ ] Sandbox environment for safe PoC execution
- [ ] Variant analysis (Big Sleep style)
- [ ] Source code audit mode (Mythos style)
- [ ] Custom fine-tuned model
- [ ] Auth + PostgreSQL scan history
- [ ] Team dashboard + subscription tiers
