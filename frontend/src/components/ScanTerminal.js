import { useState, useEffect, useRef } from "react";
import { getToken } from "../services/api";

const STAGE_LABEL = {
  recon: "RECON - mapping the target",
  crawling: "CRAWL - discovering endpoints & params",
  sweeping: "SWEEP - deterministic detectors",
  business_logic: "LOGIC - business-logic abuse",
  hunting: "HUNT - adversarial agents",
  debate: "DEBATE - attacker vs defender",
  chains: "CHAINS - building attack paths",
  done: "DONE",
};

const ROLE_ICON = { attacker: "🗡️", defender: "🛡️", judge: "⚖️", system: "·" };

export default function ScanTerminal({ target, targetType, onClose, onFinished }) {
  const [lines, setLines] = useState([]);
  const [status, setStatus] = useState("connecting");
  const [verify, setVerify] = useState(null);
  const wsRef = useRef(null);
  const boxRef = useRef(null);

  const push = (text, kind = "log") =>
    setLines((l) => [...l, { text, kind, id: l.length }]);

  useEffect(() => {
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${window.location.host}/api/v2/scans/stream`);
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus("running");
      push(`$ kryx scan ${target}  (${targetType})`, "cmd");
      ws.send(JSON.stringify({ token: getToken(), target, target_type: targetType }));
    };

    ws.onmessage = (ev) => {
      let msg;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      const { event, data } = msg;
      switch (event) {
        case "scan_started":
          push(`▶ scan #${data.scan_id} started - model tier: ${data.model_tier}`, "info");
          break;
        case "status":
          push(`\n━━ ${STAGE_LABEL[data] || data} ━━`, "stage");
          break;
        case "recon":
          push(`  recon: ${JSON.stringify(data).slice(0, 160)}`, "dim");
          break;
        case "crawl":
          push(`  crawled ${data.endpoints} endpoints`, "dim");
          break;
        case "sweep":
          push(`  sweep: ${data.findings} raw signals`, "dim");
          break;
        case "hunter_step":
          push(
            `  [${data.attack_class}] #${data.step} ${data.useful ? "★" : "·"} ${data.tool} - ${(data.thought || "").slice(0, 90)}`,
            data.useful ? "hit" : "dim"
          );
          break;
        case "findings_raw":
          push(`  → ${Array.isArray(data) ? data.length : data} raw findings`, "info");
          break;
        case "debate":
          push(`  ${ROLE_ICON[data.role] || ""} ${(data.text || "").slice(0, 130)}`, "debate");
          break;
        case "findings_validated":
          push(`  ✓ ${Array.isArray(data) ? data.length : data} validated`, "ok");
          break;
        case "chains":
          push(`  ⛓ ${Array.isArray(data) ? data.length : data} attack chains`, "ok");
          break;
        case "report":
          push(`\n${data.summary || ""}`, "summary");
          break;
        case "verify_required":
          setVerify(data);
          setStatus("verify");
          push(`✗ domain ownership not verified - see instructions below`, "err");
          break;
        case "complete":
          setStatus("done");
          push(`\n✔ scan complete - open it in the list for the full report.`, "ok");
          if (onFinished) onFinished();
          break;
        case "error":
          setStatus("error");
          push(`✗ ${typeof data === "string" ? data : JSON.stringify(data)}`, "err");
          break;
        default:
          break;
      }
    };

    ws.onerror = () => push("✗ connection error", "err");
    ws.onclose = () => setStatus((s) => (s === "running" ? "closed" : s));

    return () => {
      try {
        ws.close();
      } catch {
        /* noop */
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (boxRef.current) boxRef.current.scrollTop = boxRef.current.scrollHeight;
  }, [lines]);

  return (
    <div style={s.overlay} onClick={onClose}>
      <div style={s.panel} onClick={(e) => e.stopPropagation()}>
        <div style={s.head}>
          <span>
            <span style={{ ...s.dot, background: DOT[status] || "#888" }} /> kryx - live scan{" "}
            <span style={{ color: "#666" }}>[{status}]</span>
          </span>
          <button style={s.close} onClick={onClose}>
            ✕
          </button>
        </div>

        <div ref={boxRef} style={s.box}>
          {lines.map((l) => (
            <div key={l.id} style={{ ...s.line, ...KIND[l.kind] }}>
              {l.text}
            </div>
          ))}
          {status === "running" && <div style={{ ...s.line, ...KIND.cmd }}>▌</div>}
        </div>

        {verify && (
          <div style={s.verify}>
            <strong style={{ color: "#ffd166" }}>Verify ownership of {verify.domain}</strong>
            <div style={s.vrow}>DNS TXT → host <code style={s.code}>{verify.dns.host}</code> value <code style={s.code}>{verify.dns.value}</code></div>
            <div style={s.vrow}>or file <code style={s.code}>{verify.file.url}</code> = <code style={s.code}>{verify.file.content}</code></div>
          </div>
        )}
      </div>
    </div>
  );
}

const DOT = { running: "#ffd166", done: "#2ecc71", error: "#e94560", verify: "#ff8c42", connecting: "#888" };
const KIND = {
  cmd: { color: "#2ecc71", fontWeight: "bold" },
  stage: { color: "#8ab4f8", fontWeight: "bold" },
  hit: { color: "#7ee787" },
  dim: { color: "#7a8290" },
  info: { color: "#ddd" },
  debate: { color: "#c9a7ff" },
  ok: { color: "#2ecc71" },
  err: { color: "#e94560" },
  summary: { color: "#ffd166" },
  log: { color: "#ccc" },
};
const s = {
  overlay: { position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", display: "grid", placeItems: "center", padding: 20, zIndex: 100 },
  panel: { width: "100%", maxWidth: 880, height: "82vh", display: "flex", flexDirection: "column", background: "#0b0b12", border: "1px solid #262640", borderRadius: 12, overflow: "hidden", fontFamily: "monospace" },
  head: { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", borderBottom: "1px solid #1d1d33", color: "#fff", fontSize: 14 },
  dot: { display: "inline-block", width: 9, height: 9, borderRadius: "50%", marginRight: 8 },
  close: { background: "none", border: "none", color: "#888", fontSize: 16, cursor: "pointer" },
  box: { flex: 1, overflow: "auto", padding: 16, fontSize: 12.5, lineHeight: 1.55, whiteSpace: "pre-wrap", wordBreak: "break-word" },
  line: { fontFamily: "monospace" },
  verify: { padding: 14, borderTop: "1px solid #1d1d33", background: "#11111c", fontSize: 12.5, color: "#aaa" },
  vrow: { marginTop: 6 },
  code: { color: "#2ecc71" },
};
