"""
Plan quota & budget protection - the gate that stops one user from burning the
API budget. Pins the model per tier (cheap for low tiers, Opus for paid) and
enforces monthly + concurrency limits.
"""
import quota
from utils.llm import set_model_override, get_llm, _model_override


def test_model_gating_by_tier():
    # low tiers run the cheap model; paid tiers get Opus
    assert quota.model_for("free") == quota.DEEPSEEK
    assert quota.model_for("starter") == quota.DEEPSEEK
    assert quota.model_for("pro") == quota.OPUS
    assert quota.model_for("enterprise") == quota.OPUS
    assert quota.model_for("apt") == quota.OPUS


def test_policy_accepts_enum_str_and_unknown():
    class _Tier:  # mimic SubscriptionTier enum with .value
        value = "pro"
    assert quota.policy_for(_Tier()).model == quota.OPUS
    assert quota.policy_for("PRO").model == quota.OPUS          # case-insensitive
    assert quota.policy_for("nonsense").model == quota.DEEPSEEK  # safe default (free)


def test_can_scan_limits():
    # under the monthly limit, no concurrency -> allowed
    ok, _ = quota.can_scan("starter", scans_used=5, active_scans=0)
    assert ok is True
    # at the monthly limit -> blocked
    ok, why = quota.can_scan("starter", scans_used=20, active_scans=0)
    assert ok is False and "limit" in why.lower()
    # concurrency cap (starter max_concurrent=1) -> blocked
    ok, why = quota.can_scan("starter", scans_used=0, active_scans=1)
    assert ok is False and "once" in why.lower()


def test_model_override_is_context_scoped():
    token = set_model_override("openrouter/test/model-x")
    try:
        assert get_llm().model == "openrouter/test/model-x"
    finally:
        _model_override.reset(token)
    # after reset, falls back to the default (env) model
    assert get_llm().model != "openrouter/test/model-x"
