"""
Authorization gate — the legal safety rail. If this regresses, the engine
could scan a host it isn't allowed to. These tests pin the gate's behavior:
default DENY, allow only local / explicitly-scoped / wildcard-scoped hosts.
"""
import pytest

import core.autonomous.authz as authz
from core.autonomous.authz import is_authorized


@pytest.fixture(autouse=True)
def isolated_scope(tmp_path, monkeypatch):
    """Point the gate at a controlled scope file and neutralize the bounty
    lookup, so tests don't depend on the real authorized_scopes.txt or a
    fetched bounty cache."""
    scope = tmp_path / "scopes.txt"
    scope.write_text(
        "# test scopes\n"
        "brokencrystals.com\n"
        "demo.testfire.net\n"
        "*.ginandjuice.shop\n"
    )
    monkeypatch.setattr(authz, "ALLOWLIST_FILE", scope)
    # neutralize bounty path: nothing in-scope, nothing automation-allowed
    monkeypatch.setattr("core.autonomous.discovery.load_cached_scopes", lambda: [], raising=False)
    monkeypatch.setattr("core.autonomous.bounty.automation_allowed", lambda h: False, raising=False)
    yield


@pytest.mark.parametrize("target", [
    "https://chase.com",
    "https://whitehouse.gov",
    "http://google.com",
    "https://example.org",
    "evil.ginandjuice.shop.attacker.com",   # suffix trick must NOT match wildcard
    "notginandjuice.shop",                  # must NOT match *.ginandjuice.shop base
])
def test_unauthorized_hosts_are_refused(target):
    ok, reason = is_authorized(target)
    assert ok is False, f"{target} should be DENIED but was allowed ({reason})"


@pytest.mark.parametrize("target", [
    "https://brokencrystals.com",
    "http://brokencrystals.com",
    "brokencrystals.com",                   # bare host
    "https://brokencrystals.com/api/goto?url=x",
    "https://demo.testfire.net",
])
def test_explicitly_scoped_hosts_allowed(target):
    ok, reason = is_authorized(target)
    assert ok is True, f"{target} should be ALLOWED but was denied ({reason})"


@pytest.mark.parametrize("target,allowed", [
    ("https://shop.ginandjuice.shop", True),    # subdomain matches *.
    ("https://a.b.ginandjuice.shop", True),     # nested subdomain
    ("https://ginandjuice.shop", True),         # base of the wildcard
    ("https://ginandjuice.shop.evil.com", False),
])
def test_wildcard_scope(target, allowed):
    ok, _ = is_authorized(target)
    assert ok is allowed


@pytest.mark.parametrize("target", [
    "http://127.0.0.1:8899",
    "http://localhost:8000",
    "http://192.168.0.10",
    "http://10.0.0.5",
])
def test_local_and_lab_hosts_allowed(target):
    ok, reason = is_authorized(target)
    assert ok is True, f"{target} should be ALLOWED (local) but was denied ({reason})"


@pytest.mark.parametrize("target", ["", "http://", "not a url", "://broken"])
def test_unparseable_targets_denied(target):
    ok, _ = is_authorized(target)
    assert ok is False


def test_default_is_deny():
    """A host that matches nothing must be denied, with an explanatory reason."""
    ok, reason = is_authorized("https://random-unseen-host-12345.com")
    assert ok is False
    assert "authorized scope" in reason.lower() or "refusing" in reason.lower()
