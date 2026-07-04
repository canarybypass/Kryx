"""
Kryx Console - a thin personal web UI over the engine.

Run scans from a browser (PC/phone), watch findings + fixes live. No DB, no
heavy API - just a shared access key (so a random visitor to the tunnel URL
can't use your machine to attack others). ONLY scan targets you're authorized
to test.

Run:  ./venv/bin/uvicorn webapp:app --host 0.0.0.0 --port 8000
Then expose with a tunnel (cloudflared/ngrok) to get a public URL.
"""
import os
import time
import asyncio
import secrets

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from core.harness.supervisor import Supervisor

ACCESS_KEY = (os.getenv("KRYX_WEB_KEY") or "").strip()
if not ACCESS_KEY or ACCESS_KEY in ("changeme", "change-me") or len(ACCESS_KEY) < 6:
    raise RuntimeError(
        "KRYX_WEB_KEY is unset or too weak - the console refuses to start without "
        "a real access key (anyone reaching the URL could use your machine to scan).\n"
        "Set a strong one, e.g.:\n"
        "  KRYX_WEB_KEY=$(python -c 'import secrets; print(secrets.token_urlsafe(24))') "
        "./venv/bin/uvicorn webapp:app --host 0.0.0.0 --port 8000"
    )
MAX_HUNTERS = int(os.getenv("KRYX_HUNTERS", "6"))

app = FastAPI(title="Kryx Console")
SCANS: dict = {}


@app.get("/", response_class=HTMLResponse)
def index():
    return PAGE


@app.post("/api/scan")
async def start_scan(req: Request):
    body = await req.json()
    if body.get("key") != ACCESS_KEY:
        raise HTTPException(401, "Wrong access key")
    target = (body.get("target") or "").strip()
    if not target:
        raise HTTPException(400, "No target")
    if not target.startswith("http"):
        target = "http://" + target

    sid = secrets.token_hex(4)
    SCANS[sid] = {"target": target, "status": "queued", "stage": "", "findings": [],
                  "stats": {}, "started": time.time(), "error": None}
    asyncio.create_task(_run(sid, target))
    return {"scan_id": sid}


async def _run(sid: str, target: str):
    SCANS[sid]["status"] = "running"

    async def cb(update):
        ev, data = update.get("event"), update.get("data")
        if ev == "status":
            SCANS[sid]["stage"] = data
        elif ev == "crawl":
            SCANS[sid]["stage"] = f"crawled {data.get('endpoints')} endpoints"
        elif ev == "findings_raw":
            SCANS[sid]["findings"] = data

    try:
        res = await Supervisor(target, max_hunters=MAX_HUNTERS, progress_cb=cb).run()
        SCANS[sid]["findings"] = res.get("vulnerabilities", [])
        SCANS[sid]["stats"] = res.get("stats", {})
        SCANS[sid]["status"] = "done"
    except Exception as e:
        SCANS[sid]["status"] = "error"
        SCANS[sid]["error"] = f"{type(e).__name__}: {e}"


@app.get("/api/scan/{sid}")
def scan_status(sid: str):
    s = SCANS.get(sid)
    if not s:
        raise HTTPException(404, "Unknown scan")
    findings = [{
        "name": f.get("name", "?"),
        "severity": f.get("severity", "low"),
        "source": f.get("source", "llm"),
        "evidence": str(f.get("evidence", ""))[:400],
        "poc": str(f.get("poc", "") or f.get("steps_to_reproduce", ""))[:300],
        "remediation": f.get("remediation") or f.get("recommendation") or "",
        "fix_code": f.get("fix_code", ""),
    } for f in s["findings"]]
    return {"status": s["status"], "stage": s.get("stage", ""), "error": s.get("error"),
            "elapsed": int(time.time() - s["started"]), "stats": s.get("stats", {}),
            "findings": findings}


PAGE = """<!doctype html><html lang=ru><head>
<meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Kryx Console</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 system-ui,sans-serif;background:#0b0e14;color:#e6e6e6}
.wrap{max-width:760px;margin:0 auto;padding:18px}
h1{font-size:22px;margin:8px 0;letter-spacing:1px}
.sub{color:#8a94a6;font-size:13px;margin-bottom:18px}
input{width:100%;padding:12px;margin:6px 0;border:1px solid #2a3142;border-radius:10px;background:#121723;color:#fff;font-size:15px}
button{width:100%;padding:13px;border:0;border-radius:10px;background:#3b82f6;color:#fff;font-size:16px;font-weight:600}
button:disabled{opacity:.5}
.status{margin:14px 0;padding:10px 12px;border-radius:10px;background:#121723;font-size:14px;color:#9fb3d1}
.f{border:1px solid #1f2636;border-radius:12px;padding:12px;margin:10px 0;background:#111623}
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:700;text-transform:uppercase}
.critical{background:#7f1d1d;color:#fecaca}.high{background:#7c2d12;color:#fed7aa}
.medium{background:#713f12;color:#fde68a}.low{background:#1e3a5f;color:#bfdbfe}
.fname{font-weight:600;margin:6px 0}
.src{font-size:11px;color:#6b7689}
pre{white-space:pre-wrap;word-break:break-word;background:#0c1118;border:1px solid #1f2636;border-radius:8px;padding:9px;font-size:12px;color:#cbd5e1;margin:6px 0}
.lbl{font-size:11px;color:#8a94a6;text-transform:uppercase;margin-top:8px}
.fix{border-left:3px solid #22c55e}
.warn{color:#f59e0b;font-size:12px;margin-top:10px}
</style></head><body><div class=wrap>
<h1>⚡ KRYX</h1>
<div class=sub>AI offensive security - find · prove · fix</div>
<input id=key type=password placeholder="Access key">
<input id=target placeholder="target (e.g. https://example.com)">
<button id=go onclick=scan()>Запустить скан</button>
<div class=warn>⚠ Только цели, которые ты имеешь право тестировать.</div>
<div id=status class=status style=display:none></div>
<div id=findings></div>
</div><script>
const $=id=>document.getElementById(id);
$('key').value=localStorage.getItem('kryxkey')||'';
let timer=null;
async function scan(){
  const key=$('key').value, target=$('target').value.trim();
  localStorage.setItem('kryxkey',key);
  if(!target)return;
  $('go').disabled=true;$('findings').innerHTML='';
  $('status').style.display='block';$('status').textContent='Запускаю…';
  try{
    const r=await fetch('/api/scan',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({key,target})});
    if(!r.ok){$('status').textContent='Ошибка: '+(r.status===401?'неверный ключ':await r.text());$('go').disabled=false;return;}
    const {scan_id}=await r.json();
    if(timer)clearInterval(timer);
    timer=setInterval(()=>poll(scan_id),2500);poll(scan_id);
  }catch(e){$('status').textContent='Ошибка сети';$('go').disabled=false;}
}
async function poll(id){
  const r=await fetch('/api/scan/'+id);const s=await r.json();
  const st=s.stats||{};const sv=st.by_severity||{};
  $('status').innerHTML=`<b>${s.status}</b> · ${s.stage||''} · ${s.elapsed}s`+
    (s.findings.length?` · найдено ${s.findings.length} (🔴${sv.critical||0} 🟠${sv.high||0})`:'')+
    (s.error?`<br><span style=color:#f87171>${s.error}</span>`:'');
  render(s.findings);
  if(s.status==='done'||s.status==='error'){clearInterval(timer);$('go').disabled=false;}
}
const order={critical:0,high:1,medium:2,low:3};
function render(fs){
  fs.sort((a,b)=>(order[a.severity]??9)-(order[b.severity]??9));
  $('findings').innerHTML=fs.map(f=>`<div class=f>
    <span class="badge ${f.severity}">${f.severity}</span> <span class=src>${f.source}</span>
    <div class=fname>${esc(f.name)}</div>
    ${f.evidence?`<div class=lbl>evidence</div><pre>${esc(f.evidence)}</pre>`:''}
    ${f.poc?`<div class=lbl>PoC</div><pre>${esc(f.poc)}</pre>`:''}
    ${f.remediation?`<div class=lbl>fix</div><pre>${esc(f.remediation)}</pre>`:''}
    ${f.fix_code?`<div class=lbl>fix code</div><pre class=fix>${esc(f.fix_code)}</pre>`:''}
  </div>`).join('');
}
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
</script></body></html>"""
