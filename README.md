# ⚡ Hexor

AI-powered penetration testing assistant. Point it at a target — get a full vulnerability report in seconds.

## Stack

- **Backend** — Python, FastAPI, OpenRouter API (LLM)
- **Frontend** — React, Axios, TailwindCSS

## Structure

```
hexor/
├── backend/
│   ├── main.py           # FastAPI app, port 8000
│   ├── api/routes.py     # POST /api/scan, GET /api/health
│   ├── utils/llm.py      # OpenRouter client (multi-model fallback)
│   ├── core/agents/      # recon, analyzer, reporter agents
│   └── requirements.txt
└── frontend/
    ├── src/
    │   ├── App.js
    │   ├── components/   # ScanForm, Results
    │   └── services/     # api.js (axios)
    └── package.json
```

## Setup

### 1. Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create .env
echo "OPENROUTER_API_KEY=your_key_here" > .env

python main.py
```

Get a free API key at [openrouter.ai](https://openrouter.ai)

### 2. Frontend

```bash
cd frontend
npm install
npm start
```

Open [http://localhost:3000](http://localhost:3000)

## How it works

1. Enter a domain or IP
2. Hexor fetches HTTP headers from the target
3. Sends data to LLM (via OpenRouter, free models)
4. Returns structured report: vulnerabilities with severity, description, recommendations

## Roadmap

- [ ] DNS / WHOIS / SSL recon
- [ ] Multi-step agents (recon → analyze → report)
- [ ] Auth + scan history (PostgreSQL)
- [ ] User dashboard
- [ ] Subscription tiers (Free / Pro / Enterprise)
