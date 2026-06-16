"""
Kryx Business-Logic Hunter — finds flaws scanners can't (negative price,
price/role tampering, missing validation).

Approach: deterministically send hypothesis mutations to each parameter
(negative/zero/low/huge values, privilege values), pre-filter to mutations the
server ACCEPTED (2xx + response changed), then let the LLM judge — using the
real baseline-vs-mutated responses — whether the abuse actually worked. This
keeps it grounded and low-noise: the LLM only confirms what's visible in the
server's own response.
"""
import json
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from utils.llm import get_llm
from core.agents.prompts import LOGIC_HUNTER_PROMPT

PRICE_KW = ("price", "amount", "total", "cost", "sum", "fee", "balance", "credit", "discount", "pay")
ROLE_KW = ("role", "admin", "is_admin", "isadmin", "user_type", "usertype", "type", "level", "privilege", "access", "perm")


def _is_num(v: str) -> bool:
    return v.lstrip("-").replace(".", "", 1).isdigit() and v not in ("", "-")


class LogicHunter:
    """Stage: hypothesis-driven business-logic testing with response-grounded LLM judging."""

    def __init__(self, surface: dict, emit_cb=None):
        self.surface = surface
        self.emit = emit_cb

    async def run(self) -> list:
        endpoints = [e for e in self.surface.get("endpoints", []) if e.get("params")]
        sem = asyncio.Semaphore(4)

        async def bounded(e):
            async with sem:
                return await self._probe(e)

        results = await asyncio.gather(*[bounded(e) for e in endpoints], return_exceptions=True)
        findings = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        return findings

    def _mutations(self, pname: str, pval: str) -> list[tuple[str, str]]:
        low = pname.lower()
        muts: list[tuple[str, str]] = []
        if _is_num(pval) or any(k in low for k in PRICE_KW):
            muts += [("negative", "-1"), ("zero", "0"), ("low", "1"), ("huge", "999999999")]
        if any(k in low for k in ROLE_KW):
            muts += [("priv", "admin"), ("priv2", "administrator")]
        return muts

    async def _probe(self, endpoint: dict) -> list:
        url = endpoint["url"]
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return []

        findings = []
        async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
            try:
                baseline = (await client.get(url)).text[:700]
            except Exception:
                return []

            for pname, pvals in qs.items():
                pval = pvals[0]
                for label, mv in self._mutations(pname, pval):
                    tp = {k: v[0] for k, v in qs.items()}
                    tp[pname] = mv
                    turl = urlunparse(parsed._replace(query=urlencode(tp)))
                    try:
                        r = await client.get(turl)
                    except Exception:
                        continue
                    body = r.text[:700]
                    # pre-filter: server accepted it and the response actually changed
                    if r.status_code < 400 and body and body != baseline:
                        verdict = await self._judge(url, pname, pval, mv, baseline, body)
                        if verdict and verdict.get("vulnerable"):
                            findings.append({
                                "name": f"Business Logic: {verdict.get('type', 'flaw')} в параметре {pname} ({endpoint.get('path', url)})",
                                "severity": verdict.get("severity", "high"),
                                "attack_class": "business_logic",
                                "description": verdict.get("impact", ""),
                                "evidence": f"{pname}={pval} -> {mv}; ответ: {verdict.get('evidence', '')[:300]}",
                                "remediation": verdict.get("remediation", ""),
                                "exploitability": "confirmed",
                                "source": "logic",
                                "url": turl,
                            })
                            if self.emit:
                                await self.emit("logic_hit", {"param": pname, "url": turl})
                            break  # one finding per param
        return findings

    async def _judge(self, url, orig_param, orig_val, mut_val, baseline, mutated) -> dict | None:
        prompt = (
            f"Endpoint: {url}\nПараметр: {orig_param}\n"
            f"Нормальное значение: {orig_val}\nПодозрительное значение: {mut_val}\n\n"
            f"Ответ сервера на НОРМАЛЬНОЕ:\n{baseline}\n\n"
            f"Ответ сервера на ПОДОЗРИТЕЛЬНОЕ:\n{mutated}\n\n"
            f"Продемонстрирована ли business-logic уязвимость?"
        )
        try:
            return _parse_json(await get_llm().ask(LOGIC_HUNTER_PROMPT, prompt))
        except Exception:
            return None


def _parse_json(text: str) -> dict | None:
    import re
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except Exception:
                pass
    return None
