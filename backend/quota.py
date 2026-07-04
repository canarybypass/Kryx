"""
Plan quota & budget protection for self-serve scans.

Each plan tier maps to:
  - which LLM model runs - cheap DeepSeek for low tiers, Opus for paid, so a
    single user (or abuser) can't burn the whole API budget;
  - how many scans per month;
  - how many scans may run at once.

The SaaS layer calls can_scan() before starting a scan and pins the tier's
model via utils.llm.set_model_override().
"""
from dataclasses import dataclass

# Model ids (OpenRouter). Cheap workhorse vs premium reasoning.
DEEPSEEK = "openrouter/deepseek/deepseek-chat-v3-0324"
OPUS = "openrouter/anthropic/claude-opus-4.8"


@dataclass(frozen=True)
class TierPolicy:
    model: str
    monthly_scans: int
    max_concurrent: int


# Keyed by db.SubscriptionTier value. "free" is the default for trial / unknown.
TIER_POLICY: dict[str, TierPolicy] = {
    "free":       TierPolicy(DEEPSEEK, monthly_scans=2,      max_concurrent=1),
    "starter":    TierPolicy(DEEPSEEK, monthly_scans=20,     max_concurrent=1),   # $99
    "pro":        TierPolicy(OPUS,     monthly_scans=200,    max_concurrent=3),   # $499
    "enterprise": TierPolicy(OPUS,     monthly_scans=2000,   max_concurrent=8),   # $2999
    "apt":        TierPolicy(OPUS,     monthly_scans=100000, max_concurrent=16),  # $9999
}
_DEFAULT = TIER_POLICY["free"]


def policy_for(tier) -> TierPolicy:
    """Accepts a SubscriptionTier enum, its .value, or a plain string."""
    key = getattr(tier, "value", tier)
    return TIER_POLICY.get(str(key).lower(), _DEFAULT)


def model_for(tier) -> str:
    return policy_for(tier).model


def can_scan(tier, scans_used: int, active_scans: int) -> tuple[bool, str]:
    """Gate a new scan against the tier's monthly + concurrency limits."""
    p = policy_for(tier)
    if scans_used >= p.monthly_scans:
        return False, (f"Monthly scan limit reached ({p.monthly_scans}). "
                       f"Upgrade your plan for more.")
    if active_scans >= p.max_concurrent:
        return False, (f"Too many scans running at once (max {p.max_concurrent}). "
                       f"Wait for one to finish.")
    return True, "ok"
