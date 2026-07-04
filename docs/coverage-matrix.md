# Kryx - Coverage Matrix

Mapping of the Kryx engine's probes against the canonical web/app attack-technique
taxonomy ([PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings),
63 categories). Status: ✅ covered · 🟡 partial · ❌ missing · 🚫 intentionally skipped.

> Proof-by-execution: every ✅ is a real tool/probe that confirms with evidence,
> not a signature guess. The hunter LLM decides *when* to call each.

| # | Category | Status | Probe / Tool |
|---|----------|--------|--------------|
| 1 | API Key Leaks | ✅ | gitleaks, sensitive_files |
| 2 | Account Takeover | 🟡 | via jwt_probe / nosql_probe / host_header_probe (no dedicated chain) |
| 3 | Brute Force / Rate Limit | ❌ | - (planned: rate_limit_probe) |
| 4 | Business Logic Errors | 🟡 | LogicHunter (price/role only - top priority to deepen) |
| 5 | CORS Misconfiguration | ✅ | cors_probe |
| 6 | CRLF Injection | ✅ | crlf_probe |
| 7 | CSS Injection | ❌ | - (low severity) |
| 8 | CSV Injection | ❌ | - (low severity) |
| 9 | CVE Exploits | ✅ | nuclei_scan, cve_lookup, msf_search/run |
| 10 | Clickjacking | ✅ | headers_probe |
| 11 | Client-Side Path Traversal | ❌ | - |
| 12 | Command Injection | ✅ | cmdi_probe |
| 13 | CSRF | ✅ | csrf_probe |
| 14 | DNS Rebinding | ❌ | - (niche) |
| 15 | DOM Clobbering | ❌ | - |
| 16 | Denial of Service | 🚫 | never run against client infra (destructive) |
| 17 | Dependency Confusion | ❌ | - (white-box; planned) |
| 18 | Directory Traversal | ✅ | lfi_probe |
| 19 | Encoding Transformations | 🟡 | technique used inside other probes |
| 20 | External Variable Modification | ❌ | - |
| 21 | File Inclusion (LFI/RFI) | ✅ | lfi_probe |
| 22 | Google Web Toolkit | ❌ | - (niche) |
| 23 | GraphQL Injection | ✅ | graphql_probe (introspection; field-injection 🟡) |
| 24 | HTTP Parameter Pollution | ✅ | hpp_probe |
| 25 | Headless Browser | ✅ | browser_probe (Playwright) |
| 26 | Hidden Parameters | ✅ | param_miner |
| 27 | Insecure Deserialization | ✅ | deserialization_probe (detection → manual gadget) |
| 28 | IDOR / BOLA | ✅ | idor_probe |
| 29 | Insecure Management Interface | ✅ | open_mgmt_probe |
| 30 | Insecure Randomness | ❌ | - |
| 31 | Insecure Source Code Mgmt | ✅ | sensitive_files (.git/.svn) |
| 32 | JSON Web Token | ✅ | jwt_probe (alg=none, weak-secret crack) |
| 33 | Java RMI | ❌ | - (niche) |
| 34 | LDAP Injection | ✅ | ldap_probe |
| 35 | LaTeX Injection | ❌ | - (niche) |
| 36 | Mass Assignment | 🟡 | partial via json bodies (planned: mass_assignment_probe) |
| 37 | NoSQL Injection | ✅ | nosql_probe |
| 38 | OAuth Misconfiguration | ❌ | - (planned: oauth_probe) |
| 39 | ORM Leak | ❌ | - |
| 40 | Open Redirect | ✅ | open_redirect_probe |
| 41 | Prompt Injection | ❌ | - (planned - fits AI-app targets) |
| 42 | Prototype Pollution | ✅ | prototype_pollution_probe |
| 43 | Race Condition | ❌ | - (planned: race_probe - high value, easy) |
| 44 | Regular Expression (ReDoS) | ❌ | - (planned) |
| 45 | Request Smuggling | ✅ | smuggling_probe (CL.TE timing, conservative) |
| 46 | Reverse Proxy Misconfig | 🟡 | host_header_probe / cache_probe |
| 47 | SAML Injection | ❌ | - (planned: saml_probe) |
| 48 | SQL Injection | ✅ | sqlmap_check (level 3 / risk 2) |
| 49 | Server-Side Includes | ✅ | ssi_probe |
| 50 | SSRF | ✅ | ssrf_probe + cloud_metadata_probe |
| 51 | SSTI | ✅ | ssti_probe |
| 52 | Tabnabbing | ❌ | - (low severity) |
| 53 | Type Juggling | ❌ | - (PHP-specific) |
| 54 | Upload Insecure Files | ✅ | upload_probe |
| 55 | Virtual Hosts | 🟡 | host_header_probe (no dedicated vhost brute) |
| 56 | Web Cache Deception/Poisoning | ✅ | cache_probe |
| 57 | Web Sockets (CSWSH) | ✅ | websocket_probe |
| 58 | XPATH Injection | ✅ | xpath_probe |
| 59 | XS-Leaks | ❌ | - (niche) |
| 60 | XSLT Injection | ❌ | - (niche) |
| 61 | XSS (reflected/stored/DOM) | ✅ | xss_probe, dom_xss_probe |
| 62 | XXE Injection | ✅ | xxe_probe |
| 63 | Zip Slip | ❌ | - (upload-chain, niche) |

**Bonus (not in the 63, high value):** SSRF → cloud metadata → instance credentials - `cloud_metadata_probe` (AWS/GCP/Azure).

## Score
- ✅ Covered: **~32**
- 🟡 Partial: **~6**
- ❌ / 🚫 Missing or skipped: **~25** (mostly low-severity long-tail)

## Next add-candidates (high value, deterministic, $0)
1. **race_probe** - concurrent-request race conditions (double-spend, limit overrun). Easy, rare among competitors.
2. **mass_assignment_probe** - inject privileged fields (role/isAdmin) into JSON bodies.
3. **rate_limit_probe** - confirm missing rate limiting on auth/sensitive endpoints.
4. **oauth_probe** / **saml_probe** - auth-flow misconfig (redirect_uri, state, signature).
5. **Deepen LogicHunter** - the real moat (70% of critical bugs are business logic).
