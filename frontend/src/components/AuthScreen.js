import { useState } from "react";
import { api } from "../services/api";

export default function AuthScreen({ onAuthed }) {
  const [mode, setMode] = useState("login"); // login | register
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const submit = async (e) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const fn = mode === "login" ? api.login : api.register;
      const { access_token } = await fn(email.trim(), password);
      await onAuthed(access_token);
    } catch (err) {
      const d = err.detail;
      setError(typeof d === "string" ? d : "Something went wrong. Try again.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={s.wrap}>
      <div style={s.card}>
        <div style={s.brand}>
          <span style={s.dot} /> Kryx
        </div>
        <p style={s.tag}>Autonomous penetration testing</p>

        <form onSubmit={submit} style={s.form}>
          <input
            style={s.input}
            type="email"
            placeholder="you@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoFocus
          />
          <input
            style={s.input}
            type="password"
            placeholder={mode === "register" ? "Password (8+ chars)" : "Password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          {error && <div style={s.error}>{error}</div>}
          <button style={s.button} type="submit" disabled={busy}>
            {busy ? "…" : mode === "login" ? "Log in" : "Create account"}
          </button>
        </form>

        <div style={s.switch}>
          {mode === "login" ? "No account?" : "Already have one?"}{" "}
          <button
            style={s.link}
            onClick={() => {
              setError(null);
              setMode(mode === "login" ? "register" : "login");
            }}
          >
            {mode === "login" ? "Sign up" : "Log in"}
          </button>
        </div>
      </div>
    </div>
  );
}

const s = {
  wrap: {
    minHeight: "100vh",
    display: "grid",
    placeItems: "center",
    background: "#0f0f1a",
    color: "#fff",
    fontFamily: "monospace",
    padding: 24,
  },
  card: {
    width: "100%",
    maxWidth: 380,
    background: "#16162a",
    border: "1px solid #262640",
    borderRadius: 14,
    padding: 32,
  },
  brand: { fontSize: 26, fontWeight: "bold", display: "flex", alignItems: "center", gap: 10 },
  dot: {
    width: 12,
    height: 12,
    borderRadius: "50%",
    background: "#e94560",
    boxShadow: "0 0 16px 3px #e94560",
    display: "inline-block",
  },
  tag: { color: "#888", margin: "6px 0 26px" },
  form: { display: "flex", flexDirection: "column", gap: 12 },
  input: {
    padding: "12px 14px",
    fontSize: 15,
    borderRadius: 8,
    border: "1px solid #333",
    background: "#0f0f1a",
    color: "#fff",
    outline: "none",
  },
  button: {
    padding: "12px",
    fontSize: 15,
    borderRadius: 8,
    background: "#e94560",
    color: "#fff",
    border: "none",
    cursor: "pointer",
    fontWeight: "bold",
    marginTop: 4,
  },
  error: { color: "#e94560", fontSize: 13 },
  switch: { marginTop: 20, color: "#888", fontSize: 13 },
  link: {
    background: "none",
    border: "none",
    color: "#ffd166",
    cursor: "pointer",
    fontSize: 13,
    fontFamily: "monospace",
    padding: 0,
  },
};
