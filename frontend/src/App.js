import { useState, useEffect } from "react";
import { api, getToken, setToken, clearToken } from "./services/api";
import AuthScreen from "./components/AuthScreen";
import Dashboard from "./components/Dashboard";

export default function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!getToken()) {
      setLoading(false);
      return;
    }
    api
      .me()
      .then(setUser)
      .catch(() => clearToken())
      .finally(() => setLoading(false));
  }, []);

  const onAuthed = async (token) => {
    setToken(token);
    const u = await api.me();
    setUser(u);
  };

  const logout = () => {
    clearToken();
    setUser(null);
  };

  if (loading) {
    return <div style={S.boot}>Kryx…</div>;
  }

  return user ? (
    <Dashboard user={user} onLogout={logout} />
  ) : (
    <AuthScreen onAuthed={onAuthed} />
  );
}

const S = {
  boot: {
    minHeight: "100vh",
    display: "grid",
    placeItems: "center",
    background: "#0f0f1a",
    color: "#e94560",
    fontFamily: "monospace",
    fontSize: 20,
  },
};
