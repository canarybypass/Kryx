"""
Domain ownership verification - the self-serve legal gate. These cover the
pure, deterministic pieces (token + normalization + instructions). The async
DNS/HTTP checks hit the network and are exercised in integration, not here.
"""
from ownership import normalize_domain, verification_token, instructions


def test_normalize_strips_scheme_path_port_wildcard():
    assert normalize_domain("https://Acme.com/app?x=1") == "acme.com"
    assert normalize_domain("acme.com:443") == "acme.com"
    assert normalize_domain("*.acme.com") == "acme.com"
    assert normalize_domain("  ACME.COM  ") == "acme.com"


def test_token_is_deterministic_per_org_and_domain():
    a = verification_token(1, "acme.com")
    assert a == verification_token(1, "acme.com")          # stable
    assert a == verification_token(1, "https://acme.com/")  # normalized first
    assert a != verification_token(2, "acme.com")           # differs per org
    assert a != verification_token(1, "other.com")          # differs per domain
    assert a.startswith("kryx-verify-")


def test_instructions_shape():
    info = instructions(7, "Example.com")
    assert info["domain"] == "example.com"
    assert info["token"] == verification_token(7, "example.com")
    assert info["dns"]["type"] == "TXT"
    assert info["dns"]["value"] == info["token"]
    assert info["file"]["url"].endswith("/.well-known/kryx-verify.txt")
    assert info["file"]["content"] == info["token"]
