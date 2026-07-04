"""
Kryx Scan Memory - cumulative per-target knowledge across scans.

Each scan remembers a target's attack surface and findings. The next scan of
the same target starts from the accumulated surface (never loses endpoints),
and the LLM hunters see what was found before (verify fixes, dig deeper).
The more a target is scanned, the smarter the agent gets on it.
"""
import json
import time
from pathlib import Path
from urllib.parse import urlparse

STORE = Path(__file__).parent / "scan_memory.json"


def _host(target: str) -> str:
    if "://" not in target:
        target = "http://" + target
    return (urlparse(target).hostname or target).lower()


def _load() -> dict:
    if STORE.exists():
        try:
            return json.loads(STORE.read_text())
        except Exception:
            return {}
    return {}


def _save(d: dict):
    STORE.write_text(json.dumps(d, ensure_ascii=False, indent=2))


def recall(target: str) -> dict:
    """Past knowledge for a target (empty dict if first scan)."""
    return _load().get(_host(target), {})


def remember(target: str, endpoints: list[dict], findings: list[dict]) -> dict:
    """Persist this scan, accumulating endpoints across runs."""
    d = _load()
    h = _host(target)
    prev = d.get(h, {})

    # Accumulate endpoints (union by path+params) so re-scans never lose surface.
    seen = {(e.get("path"), tuple(sorted(e.get("params", [])))): e
            for e in prev.get("endpoints", [])}
    for e in endpoints:
        seen[(e.get("path"), tuple(sorted(e.get("params", []))))] = {
            "url": e.get("url"), "path": e.get("path"), "params": e.get("params", [])}

    d[h] = {
        "host": h,
        "last_scanned": time.strftime("%Y-%m-%d %H:%M"),
        "scan_count": prev.get("scan_count", 0) + 1,
        "endpoints": list(seen.values()),
        "findings": [{"name": f.get("name"), "severity": f.get("severity"),
                      "attack_class": f.get("attack_class")} for f in findings],
    }
    _save(d)
    return d[h]


def memory_context(mem: dict) -> str:
    """Human/LLM-readable summary of past knowledge to inject into hunters."""
    if not mem or not mem.get("findings"):
        return ""
    lines = [f"ПАМЯТЬ ПО ЦЕЛИ (скан #{mem.get('scan_count')}). Ранее найдено:"]
    for f in mem["findings"][:15]:
        lines.append(f"  - [{f.get('severity')}] {f.get('name')}")
    lines.append("Проверь, исправлены ли они, и копай глубже в этих местах/классах.")
    return "\n".join(lines)
