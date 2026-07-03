import { useState, useEffect, useCallback, useRef } from "react";
import { api } from "../services/api";
import ScanDetail from "./ScanDetail";

const ACTIVE = new Set(["queued", "running"]);

export default function Dashboard({ user, onLogout }) {
  const [usage, setUsage] = useState(null);
  const [scans, setScans] = useState([]);
  const [selected, setSelected] = useState(null);

  const [target, setTarget] = useState("");
  const [type, setType] = useState("web");
  const [creating, setCreating] = useState(false);
  const [verify, setVerify] = useState(null); // ownership instructions object
  const [error, setError] = useState(null);
  const pollRef = useRef(null);

  const refresh = useCallback(async () => {
    try {
      const [u, list] = await Promise.all([api.usage(), api.listScans()]);
      setUsage(u);
      setScans(list);
    } catch {
      /* token may be stale — App handles 401 on next load */
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Poll while any scan is queued/running.
  useEffect(() => {
    const anyActive = scans.some((s) => ACTIVE.has(s.status));
    clearInterval(pollRef.current);
    if (anyActive) pollRef.current = setInterval(refresh, 5000);
    return () => clearInterval(pollRef.current);
  }, [scans, refresh]);

  const runScan = async (e) => {
    e.preventDefault();
    setError(null);
    setVerify(null);
    setCreating(true);
    try {
      await api.createScan(target.trim(), type);
      setTarget("");
      await refresh();
    } catch (err) {
      const d = err.detail;
      if (err.status === 403 && d && typeof d === "object" && d.instructions) {
        setVerify(d.instructions); // domain ownership gate
      } else {
        setError(typeof d === "string" ? d : "Could not start scan.");
      }
    } finally {
      setCreating(false);
    }
  };

  return (
    <div style={s.page}>
      <header style={s.top}>
        <div style={s.brand}>
          <span style={s.dot} /> Kryx
        </div>
        <div style={s.user}>
          <span style={{ color: "#888" }}>{user.email}</span>
          <button style={s.logout} onClick={onLogout}>
            Log out
          </button>
        </div>
      </header>

      <main style={s.main}>
        {usage && <UsageBar usage={usage} />}

        <section style={s.card}>
          <h2 style={s.h2}>New scan</h2>
          <form onSubmit={runScan} style={s.form}>
            <select style={s.select} value={type} onChange={(e) => setType(e.target.value)}>
              <option value="web">Web / URL</option>
              <option value="repo">Git repo</option>
            </select>
            <input
              style={s.input}
              placeholder={type === "web" ? "https://yourapp.com" : "https://github.com/org/repo"}
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              required
            />
            <button style={s.run} type="submit" disabled={creating}>
              {creating ? "Starting…" : "Run scan"}
            </button>
          </form>
          {error && <div style={s.err}>{error}</div>}
          {verify && <VerifyPanel ins={verify} onRetry={runScan} />}
        </section>

        <section style={s.card}>
          <h2 style={s.h2}>Scans</h2>
          {scans.length === 0 ? (
            <p style={{ color: "#888" }}>No scans yet. Run your first one above.</p>
          ) : (
            <table style={s.table}>
              <thead>
                <tr style={{ color: "#888", textAlign: "left" }}>
                  <th style={s.th}>Target</th>
                  <th style={s.th}>Status</th>
                  <th style={s.th}>Findings</th>
                  <th style={s.th}>When</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((sc) => (
                  <tr key={sc.id} style={s.tr} onClick={() => setSelected(sc.id)}>
                    <td style={s.td}>{sc.target}</td>
                    <td style={s.td}>
                      <StatusBadge status={sc.status} />
                    </td>
                    <td style={s.td}>{severitySummary(sc.stats)}</td>
                    <td style={{ ...s.td, color: "#888" }}>{fmtDate(sc.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </main>

      {selected && <ScanDetail scanId={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function UsageBar({ usage }) {
  const used = usage.monthly_scans_used ?? 0;
  const limit = usage.monthly_scan_limit ?? 0;
  const pct = limit ? Math.min(100, Math.round((used / limit) * 100)) : 0;
  return (
    <section style={s.card}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10 }}>
        <span>
          Plan: <strong style={{ color: "#ffd166" }}>{String(usage.subscription_tier)}</strong>{" "}
          <span style={{ color: "#888" }}>({usage.subscription_status})</span>
        </span>
        <span style={{ color: "#888" }}>
          {used} / {limit} scans this month
        </span>
      </div>
      <div style={s.barTrack}>
        <div style={{ ...s.barFill, width: `${pct}%` }} />
      </div>
    </section>
  );
}

function VerifyPanel({ ins, onRetry }) {
  return (
    <div style={s.verify}>
      <strong style={{ color: "#ffd166" }}>Verify you own {ins.domain}</strong>
      <p style={{ color: "#aaa", margin: "8px 0" }}>
        Add ONE of the following, then re-run the scan:
      </p>
      <div style={s.option}>
        <div style={s.optTitle}>Option A — DNS TXT record</div>
        <Code label="Host" value={ins.dns.host} />
        <Code label="Type" value={ins.dns.type} />
        <Code label="Value" value={ins.dns.value} />
      </div>
      <div style={s.option}>
        <div style={s.optTitle}>Option B — file on the site</div>
        <Code label="URL" value={ins.file.url} />
        <Code label="Content" value={ins.file.content} />
      </div>
      <button style={s.run} onClick={onRetry}>
        I've added it — re-run scan
      </button>
    </div>
  );
}

function Code({ label, value }) {
  return (
    <div style={{ display: "flex", gap: 8, margin: "3px 0", fontSize: 13 }}>
      <span style={{ color: "#888", minWidth: 64 }}>{label}:</span>
      <code style={s.code}>{value}</code>
    </div>
  );
}

function StatusBadge({ status }) {
  const color =
    status === "completed" ? "#2ecc71" : status === "failed" ? "#e94560" : "#ffd166";
  return (
    <span style={{ color, border: `1px solid ${color}`, borderRadius: 6, padding: "2px 8px", fontSize: 12 }}>
      {status}
    </span>
  );
}

function severitySummary(stats) {
  const by = (stats && stats.by_severity) || {};
  const parts = [];
  if (by.critical) parts.push(`${by.critical}C`);
  if (by.high) parts.push(`${by.high}H`);
  if (by.medium) parts.push(`${by.medium}M`);
  if (by.low) parts.push(`${by.low}L`);
  return parts.length ? parts.join(" · ") : "—";
}

function fmtDate(d) {
  if (!d) return "";
  try {
    return new Date(d).toLocaleString();
  } catch {
    return d;
  }
}

const s = {
  page: { minHeight: "100vh", background: "#0f0f1a", color: "#fff", fontFamily: "monospace" },
  top: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "16px 28px",
    borderBottom: "1px solid #262640",
  },
  brand: { fontSize: 20, fontWeight: "bold", display: "flex", alignItems: "center", gap: 10 },
  dot: { width: 10, height: 10, borderRadius: "50%", background: "#e94560", boxShadow: "0 0 14px 2px #e94560" },
  user: { display: "flex", alignItems: "center", gap: 14, fontSize: 14 },
  logout: { background: "none", border: "1px solid #333", color: "#ccc", borderRadius: 6, padding: "6px 12px", cursor: "pointer", fontFamily: "monospace" },
  main: { maxWidth: 980, margin: "0 auto", padding: "28px 20px", display: "flex", flexDirection: "column", gap: 20 },
  card: { background: "#16162a", border: "1px solid #262640", borderRadius: 12, padding: 22 },
  h2: { margin: "0 0 16px", fontSize: 16 },
  form: { display: "flex", gap: 10, flexWrap: "wrap" },
  select: { padding: "11px 12px", borderRadius: 8, border: "1px solid #333", background: "#0f0f1a", color: "#fff" },
  input: { flex: 1, minWidth: 220, padding: "11px 14px", borderRadius: 8, border: "1px solid #333", background: "#0f0f1a", color: "#fff", outline: "none" },
  run: { padding: "11px 24px", borderRadius: 8, background: "#e94560", color: "#fff", border: "none", cursor: "pointer", fontWeight: "bold" },
  err: { color: "#e94560", marginTop: 12, fontSize: 14 },
  barTrack: { height: 8, background: "#0f0f1a", borderRadius: 6, overflow: "hidden" },
  barFill: { height: "100%", background: "#e94560" },
  table: { width: "100%", borderCollapse: "collapse" },
  th: { padding: "8px 6px", fontWeight: "normal", fontSize: 12, borderBottom: "1px solid #262640" },
  tr: { cursor: "pointer", borderBottom: "1px solid #1d1d33" },
  td: { padding: "12px 6px", fontSize: 14 },
  verify: { marginTop: 16, padding: 16, background: "#0f0f1a", border: "1px solid #ffd16633", borderRadius: 10 },
  option: { margin: "12px 0", padding: 12, background: "#16162a", borderRadius: 8 },
  optTitle: { color: "#ccc", marginBottom: 8, fontSize: 13 },
  code: { color: "#2ecc71", wordBreak: "break-all" },
};
