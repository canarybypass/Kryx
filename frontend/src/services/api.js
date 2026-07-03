// Kryx dashboard API client. Token-aware fetch over the nginx /api proxy.
const BASE = "/api";
const TOKEN_KEY = "kryx_token";

export const getToken = () => localStorage.getItem(TOKEN_KEY);
export const setToken = (t) => localStorage.setItem(TOKEN_KEY, t);
export const clearToken = () => localStorage.removeItem(TOKEN_KEY);

async function req(path, { method = "GET", body, auth = true } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (auth) {
    const t = getToken();
    if (t) headers.Authorization = `Bearer ${t}`;
  }
  const res = await fetch(BASE + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!res.ok) {
    const err = new Error("request_failed");
    err.status = res.status;
    // FastAPI puts the payload under `detail` (a string for the quota gate,
    // an object with ownership instructions for the domain gate).
    err.detail = data && data.detail !== undefined ? data.detail : data;
    throw err;
  }
  return data;
}

export const api = {
  register: (email, password) =>
    req("/auth/register", { method: "POST", body: { email, password }, auth: false }),
  login: (email, password) =>
    req("/auth/login", { method: "POST", body: { email, password }, auth: false }),
  me: () => req("/auth/me"),
  usage: () => req("/billing/usage"),
  listScans: () => req("/scans"),
  createScan: (target, target_type) =>
    req("/v2/scans", { method: "POST", body: { target, target_type } }),
  getScan: (id) => req(`/v2/scans/${id}`),
};
