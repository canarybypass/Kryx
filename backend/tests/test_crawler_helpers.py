"""
Crawler helpers behind JSON-body API discovery and asset-skipping.
"""
from core.harness.crawler import _parse_json_body, _is_asset


def test_parse_json_body_accepts_object():
    assert _parse_json_body('{"q": "hi"}') == {"q": "hi"}
    assert _parse_json_body('{"a": 1, "b": {"c": 2}}') == {"a": 1, "b": {"c": 2}}


def test_parse_json_body_rejects_non_objects():
    assert _parse_json_body("[1, 2, 3]") is None      # array, no named fields to fuzz
    assert _parse_json_body('"just a string"') is None
    assert _parse_json_body("42") is None
    assert _parse_json_body("{}") is None              # empty object: nothing to test


def test_parse_json_body_rejects_garbage():
    assert _parse_json_body("not json") is None
    assert _parse_json_body("") is None
    assert _parse_json_body(None) is None
    assert _parse_json_body("key=value&x=1") is None   # urlencoded, not JSON


def test_is_asset_skips_static_but_keeps_endpoints():
    assert _is_asset("https://x.com/app.js") is True
    assert _is_asset("https://x.com/logo.png") is True
    assert _is_asset("https://x.com/style.css?v=2") is True
    assert _is_asset("https://x.com/api/users") is False
    assert _is_asset("https://x.com/search?q=1") is False
