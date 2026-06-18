"""
Kryx Bounty Track — active scanning of bug-bounty targets, safely.

In-scope is NOT enough: many programs forbid automated scanners. So a bounty
host is only scannable if YOU have confirmed (by reading the program's policy)
that automated testing is allowed — recorded in bounty_automation_allowed.txt.
The authz gate enforces this: in-scope + automation-allowed, or it's refused.

Findings here are black-box and TOOL-CONFIRMED (proven by execution), which is
what makes them defensible to submit — unlike reasoned white-box guesses.
"""
from pathlib import Path

from core.autonomous import discovery

ALLOW_FILE = Path(__file__).parent / "bounty_automation_allowed.txt"


def _load_allow() -> list[str]:
    if not ALLOW_FILE.exists():
        return []
    return [l.strip().lower() for l in ALLOW_FILE.read_text().splitlines()
            if l.strip() and not l.lstrip().startswith("#")]


def _match(host: str, patterns: list[str]) -> bool:
    host = host.lower()
    for p in patterns:
        if p.startswith("*."):
            base = p[2:]
            if host == base or host.endswith("." + base):
                return True
        elif host == p:
            return True
    return False


def automation_allowed(host: str) -> bool:
    """True only if the user confirmed this program permits automated testing."""
    return _match(host, _load_allow())


def list_inscope_web(n: int = 30) -> list[str]:
    """Concrete in-scope domains to consider (check each program's policy before
    adding to bounty_automation_allowed.txt)."""
    return discovery.sample_targets(n)
