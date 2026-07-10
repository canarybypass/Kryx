"""
Kryx authentication stage - get the engine a real session so it reaches and tests
the surface BEHIND the login, where the high-value bugs live.

Modes:
  - Provided credentials (KRYX_LOGIN_USER / KRYX_LOGIN_PASS): safe, on by default -
    just logs in with a session-carrying client.
  - Auto-register a throwaway account (KRYX_AUTH_ACTIVE=1): OPT-IN, because creating
    an account changes state on the target. Off by default (non-destructive default).

Returns {"authenticated": bool, "cookies": {...}, "headers": {...}, "how": str}.
The Supervisor applies the session (set_auth) and re-crawls the authed surface.
"""
import os
import re
import httpx

from core.tools.probes_ext import _prep_login, _attr

_LOGIN_PATHS = ["/login", "/login.jsp", "/login.php", "/signin", "/sign-in",
                "/account/login", "/user/login", "/auth/login", "/api/login",
                "/api/auth/login", "/users/sign_in", "/session"]
_REGISTER_PATHS = ["/register", "/signup", "/sign-up", "/account/register",
                   "/user/register", "/users", "/api/register", "/api/auth/register",
                   "/registration", "/join", "/create-account"]

_FAIL_MARKERS = ("invalid", "incorrect", "wrong password", "failed", "denied",
                 "try again", "bad credentials", "not found", "unauthor")
_AUTHED_MARKERS = ("logout", "log out", "sign out", "signout", "my account",
                   "dashboard", "welcome", "profile", "settings")


def _rand(n=6):
    import secrets
    return secrets.token_hex(n)[:n]


def _client(**kw):
    return httpx.AsyncClient(timeout=12, follow_redirects=True, verify=False, **kw)


def discover_auth_endpoints(surface: dict, target: str) -> dict:
    """Find login/register endpoints from the crawl surface, else fall back to
    common paths."""
    eps = surface.get("endpoints", []) if surface else []
    login = register = None
    for e in eps:
        u = e.get("url", "")
        low = u.lower()
        if not login and re.search(r"log[\-_]?in|sign[\-_]?in|/session|auth/login", low):
            login = u
        if not register and re.search(r"regist|sign[\-_]?up|/join|create[\-_]?account", low):
            register = u
    base = target.rstrip("/")
    if base and not base.startswith("http"):
        base = "http://" + base
    return {
        "login": login or None,
        "register": register or None,
        "login_candidates": [base + p for p in _LOGIN_PATHS],
        "register_candidates": [base + p for p in _REGISTER_PATHS],
    }


def _login_ok(status: int, location: str, body: str) -> bool:
    """Did a login POST succeed? Redirect away from login, or an authed marker in
    the body with no failure marker."""
    b = (body or "").lower()
    loc = (location or "").lower()
    if status in (301, 302, 303, 307) and loc and "login" not in loc and "error" not in loc:
        return True
    if status == 200 and any(m in b for m in _AUTHED_MARKERS) and not any(m in b for m in _FAIL_MARKERS):
        return True
    return False


async def _try_login(login_url: str, user: str, password: str) -> dict | None:
    """Attempt a form then JSON login. On success returns the captured session."""
    # form login (carries CSRF token + auto-detects fields via _prep_login)
    try:
        async with _client() as c:
            post_url, hidden, uf, pf, _ = await _prep_login(c, login_url, None, None)
            r = await c.post(post_url, data={**hidden, uf: user, pf: password})
            if _login_ok(r.status_code, r.headers.get("location", ""), r.text):
                cookies = {k: v for k, v in c.cookies.items()}
                if cookies:
                    return {"cookies": cookies, "headers": {}, "how": f"form login ({uf}/{pf})"}
    except Exception:
        pass
    # JSON API login -> bearer token or session cookie
    try:
        async with _client() as c:
            r = await c.post(login_url, json={"username": user, "email": user, "password": password})
            if r.status_code < 400:
                token = None
                try:
                    j = r.json()
                    for k in ("token", "access_token", "accessToken", "jwt", "id_token"):
                        if isinstance(j, dict) and j.get(k):
                            token = j[k]
                            break
                except Exception:
                    pass
                if token:
                    return {"cookies": {}, "headers": {"Authorization": f"Bearer {token}"},
                            "how": "json login (bearer token)"}
                cookies = {k: v for k, v in c.cookies.items()}
                if cookies and _login_ok(r.status_code, "", r.text):
                    return {"cookies": cookies, "headers": {}, "how": "json login (cookie)"}
    except Exception:
        pass
    return None


async def _try_register(register_url: str, user: str, password: str, email: str) -> bool:
    """Auto-register a throwaway account (active mode only). Best-effort across
    form and JSON registration endpoints."""
    # form register - parse fields, fill username/password/email/confirm
    try:
        async with _client() as c:
            r0 = await c.get(register_url)
            html = r0.text or ""
            data = {}
            for t in re.findall(r"<input\b[^>]*>", html, re.I):
                name = _attr(t, "name")
                if not name:
                    continue
                typ = (_attr(t, "type") or "text").lower()
                val = _attr(t, "value")
                if typ == "hidden":
                    data[name] = val
                elif typ == "password":
                    data[name] = password
                elif re.search(r"email|mail", name, re.I) or typ == "email":
                    data[name] = email
                elif re.search(r"user|login|name|account", name, re.I):
                    data[name] = user
            if not any("pass" in k.lower() for k in data):
                data["password"] = password
            m = re.search(r"<form\b[^>]*\baction\s*=\s*[\"']?([^\"'>\s]+)", html, re.I)
            post_url = register_url
            if m and m.group(1) not in ("#", ""):
                from urllib.parse import urljoin
                post_url = urljoin(register_url, m.group(1))
            r = await c.post(post_url, data=data)
            if r.status_code < 400 and not any(x in (r.text or "").lower() for x in ("already", "taken", "exists")):
                return True
    except Exception:
        pass
    # JSON register
    try:
        async with _client() as c:
            r = await c.post(register_url, json={"username": user, "email": email, "password": password})
            if r.status_code < 400:
                return True
    except Exception:
        pass
    return False


class AuthnStage:
    """Obtain a session for the scan (login, or opt-in auto-register + login)."""

    def __init__(self, target: str, surface: dict, emit_cb=None):
        self.target = target
        self.surface = surface or {}
        self.emit = emit_cb

    async def _emit(self, event, data):
        if self.emit:
            await self.emit(event, data)

    async def run(self) -> dict:
        eps = discover_auth_endpoints(self.surface, self.target)
        login_urls = [u for u in [eps["login"]] if u] + eps["login_candidates"]

        user = os.getenv("KRYX_LOGIN_USER")
        password = os.getenv("KRYX_LOGIN_PASS")
        active = os.getenv("KRYX_AUTH_ACTIVE") == "1"

        # 1) Provided credentials -> just log in (safe, default).
        if user and password:
            for lu in login_urls:
                sess = await _try_login(lu, user, password)
                if sess:
                    await self._emit("authn", {"authenticated": True, "how": sess["how"], "endpoint": lu})
                    return {"authenticated": True, **sess, "endpoint": lu}

        # 2) Active mode -> register a throwaway account, then log in.
        if active:
            u = os.getenv("KRYX_LOGIN_USER") or f"kryx_{_rand()}"
            p = os.getenv("KRYX_LOGIN_PASS") or f"Kryx!{_rand()}aA1"
            email = f"{u}@example.com"
            reg_urls = [r for r in [eps["register"]] if r] + eps["register_candidates"]
            for ru in reg_urls:
                if await _try_register(ru, u, p, email):
                    for lu in login_urls:
                        sess = await _try_login(lu, u, p)
                        if sess:
                            await self._emit("authn", {"authenticated": True,
                                                       "how": f"auto-register + {sess['how']}",
                                                       "endpoint": lu, "account": u})
                            return {"authenticated": True, **sess, "endpoint": lu,
                                    "how": f"auto-register + {sess['how']}", "account": u}
                    break  # registered but couldn't log in - stop

        await self._emit("authn", {"authenticated": False,
                                    "reason": "no credentials (set KRYX_LOGIN_USER/PASS) "
                                              "and auto-register off (KRYX_AUTH_ACTIVE=1)"
                                              if not active else "login/register not found or failed"})
        return {"authenticated": False}
