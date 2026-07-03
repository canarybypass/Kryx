import { useState, useEffect, useRef } from "react";
import ReactMarkdown from "react-markdown";
import { api } from "../services/api";

const ACTIVE = new Set(["queued", "running"]);
const SEV_COLOR = { critical: "#e94560", high: "#ff8c42", medium: "#ffd166", low: "#7ee787", info: "#888" };

export default function ScanDetail({ scanId, onClose }) {
  const [scan, setScan] = useState(null);
  const [err, setErr] = useState(null);
  const pollRef = useRef(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const data = await api.getScan(scanId);
        if (!alive) return;
        setScan(data);
        if (!ACTIVE.has(data.status)) clearInterval(pollRef.current);
      } catch (e) {
        if (alive) setErr("Could not load scan.");
      }
    };
    load();
    pollRef.current = setInterval(load, 4000);
    return () => {
      alive = false;
      clearInterval(pollRef.current);
    };
  }, [scanId]);

  return (
    <div style={s.overlay} onClick={onClose}>
      <div style={s.panel} onClick={(e) => e.stopPropagation()}>
        <div style={s.head}>
          <span style={{ fontSize: 16 }}>{scan ? scan.target : `Scan #${scanId}`}</span>
          <button style={s.close} onClick={onClose}>
            ✕
          </button>
        </div>

        {err && <div style={s.err}>{err}</div>}
        {!scan && !err && <div style={{ color: "#888" }}>Loading…</div>}

        {scan && (
          <div style={s.body}>
            <div style={s.meta}>
              <span>
                Status:{" "}
                <strong style={{ color: ACTIVE.has(scan.status) ? "#ffd166" : "#2ecc71" }}>
                  {scan.status}
                </strong>
              </span>
              {ACTIVE.has(scan.status) && <span style={{ color: "#888" }}>live — updating…</span>}
            </div>

            {scan.summary && <p style={s.summary}>{scan.summary}</p>}

            <h3 style={s.h3}>Findings ({scan.vulnerabilities?.length || 0})</h3>
            {scan.vulnerabilities?.length ? (
              <div>
                {scan.vulnerabilities.map((v) => (
                  <div key={v.id} style={s.finding}>
                    <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                      <span style={{ ...s.sev, background: SEV_COLOR[v.severity] || "#888" }}>
                        {v.severity}
                      </span>
                      <strong>{v.name}</strong>
                      {v.verified && <span style={s.verified}>✓ verified</span>}
                    </div>
                    {v.location && <div style={s.loc}>{v.location}</div>}
                    {v.description && <div style={s.desc}>{v.description}</div>}
                  </div>
                ))}
              </div>
            ) : (
              <p style={{ color: "#888" }}>
                {ACTIVE.has(scan.status) ? "Scanning…" : "No confirmed findings."}
              </p>
            )}

            {scan.report && (
              <>
                <h3 style={s.h3}>Full report</h3>
                <div style={s.report}>
                  <ReactMarkdown>{scan.report}</ReactMarkdown>
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

const s = {
  overlay: { position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", display: "grid", placeItems: "center", padding: 20, zIndex: 100 },
  panel: { width: "100%", maxWidth: 820, maxHeight: "88vh", overflow: "auto", background: "#16162a", border: "1px solid #262640", borderRadius: 14, padding: 24, fontFamily: "monospace", color: "#fff" },
  head: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 },
  close: { background: "none", border: "none", color: "#888", fontSize: 18, cursor: "pointer" },
  err: { color: "#e94560" },
  body: { display: "flex", flexDirection: "column", gap: 14 },
  meta: { display: "flex", gap: 16, fontSize: 14 },
  summary: { color: "#ccc", lineHeight: 1.5, fontSize: 14, background: "#0f0f1a", padding: 14, borderRadius: 8 },
  h3: { fontSize: 14, margin: "8px 0 4px", color: "#ffd166" },
  finding: { background: "#0f0f1a", borderRadius: 8, padding: 14, marginBottom: 10 },
  sev: { color: "#0f0f1a", fontWeight: "bold", borderRadius: 5, padding: "2px 8px", fontSize: 11, textTransform: "uppercase" },
  verified: { color: "#2ecc71", fontSize: 12 },
  loc: { color: "#8ab4f8", fontSize: 13, marginTop: 6, wordBreak: "break-all" },
  desc: { color: "#aaa", fontSize: 13, marginTop: 6, lineHeight: 1.5 },
  report: { background: "#0f0f1a", borderRadius: 8, padding: "4px 18px", fontSize: 13, lineHeight: 1.6, color: "#ddd" },
};
