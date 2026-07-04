"""
Kryx Auth Context - authenticated scanning.

The user supplies a session cookie and/or auth headers (e.g. a bearer token).
Set once per scan; every TARGET-facing request (crawler, detectors, sqlmap)
sends them, so Kryx reaches and tests the authenticated surface - where the
high-value bugs live. External API calls (NVD/Shodan/LLM) must NOT use this.
"""
import httpx

_HEADERS: dict = {}
_COOKIES: dict = {}


def set_auth(headers: dict | None = None, cookies: dict | None = None):
    global _HEADERS, _COOKIES
    _HEADERS = dict(headers or {})
    _COOKIES = dict(cookies or {})


def clear_auth():
    set_auth({}, {})


def is_authed() -> bool:
    return bool(_HEADERS or _COOKIES)


def auth_headers() -> dict:
    return dict(_HEADERS)


def auth_cookies() -> dict:
    return dict(_COOKIES)


def client(**kwargs) -> httpx.AsyncClient:
    """httpx client pre-loaded with the scan's auth (for TARGET requests)."""
    headers = {**_HEADERS, **(kwargs.pop("headers", None) or {})}
    cookies = {**_COOKIES, **(kwargs.pop("cookies", None) or {})}
    return httpx.AsyncClient(headers=headers or None, cookies=cookies or None, **kwargs)


def sqlmap_args() -> list[str]:
    """--cookie / --header flags for sqlmap so it scans authenticated."""
    args: list[str] = []
    if _COOKIES:
        args += ["--cookie", "; ".join(f"{k}={v}" for k, v in _COOKIES.items())]
    for k, v in _HEADERS.items():
        args += ["--header", f"{k}: {v}"]
    return args


def parse_cookie_string(s: str) -> dict:
    """Parse 'a=1; b=2' into a dict."""
    out = {}
    for part in (s or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out
