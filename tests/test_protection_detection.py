"""recon_result["protections"] — deterministic WAF/CDN identification from nuclei's own
global-waf-detect match and WhatWeb's known WAF/CDN plugin tokens (agent/core.py's
_merge_protection_detection / _protection_task_addendum). A protective system must show up as
what it is, not buried as just another unlabeled "technology" token.
"""
import asyncio

import pytest

from agent.core import RunContext, _merge_protection_detection, _protection_task_addendum
from agent.tools.registry import ToolSpec
from sessions import store


@pytest.fixture(autouse=True)
def _isolated_session_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def _run(coro):
    return asyncio.run(coro)


def _make_ctx(session: dict | None = None) -> RunContext:
    return RunContext(llm=None, session=session or {}, session_id="usr_test123")


def _tool(name: str) -> ToolSpec:
    return ToolSpec(
        name=name, category="scan", tool_tier=2, executable=name,
        build_command=lambda args: [name], requires_allowed_target=False, installed_by_default=True,
    )


def test_nuclei_waf_detect_match_populates_protections():
    ctx = _make_ctx()
    result = {
        "status": "ok",
        "used_arguments": {"target": "https://example.com"},
        "parsed": [
            {"template_id": "global-waf-detect", "name": "Global WAF Detect Matchers", "matcher_name": "cloudflare"},
            {"template_id": "http-missing-security-headers", "name": "HTTP Missing Security Headers", "matcher_name": None},
        ],
    }
    _merge_protection_detection(ctx, _tool("nuclei"), result, {"target": "https://example.com"})
    protections = ctx.session["recon_result"]["protections"]
    assert protections == {"https://example.com": ["cloudflare (WAF, nuclei global-waf-detect)"]}


def test_nuclei_waf_detect_match_without_matcher_name_falls_back_to_generic_label():
    ctx = _make_ctx()
    result = {
        "status": "ok",
        "used_arguments": {"target": "https://example.com"},
        "parsed": [{"template_id": "global-waf-detect", "name": "Global WAF Detect Matchers", "matcher_name": None}],
    }
    _merge_protection_detection(ctx, _tool("nuclei"), result, {"target": "https://example.com"})
    assert ctx.session["recon_result"]["protections"]["https://example.com"] == [
        "Unidentified WAF (nuclei global-waf-detect)"
    ]


def test_whatweb_known_waf_plugin_token_is_recognized():
    ctx = _make_ctx()
    result = {
        "status": "ok",
        "used_arguments": {"target": "https://example.com"},
        "parsed": {"technologies": ["CloudFlare[nginx]", "jQuery[1.8.2]", "HTTPServer[Apache/2.4.41]"]},
    }
    _merge_protection_detection(ctx, _tool("whatweb"), result, {"target": "https://example.com"})
    assert ctx.session["recon_result"]["protections"]["https://example.com"] == ["CloudFlare (WAF/CDN, whatweb)"]


def test_whatweb_waf_vendor_buried_inside_a_generic_plugins_value_is_recognized():
    # Real, confirmed shape: WhatWeb's generic "HTTPServer" plugin literally echoes the Server
    # header verbatim ("cloudflare"), which never triggers WhatWeb's own dedicated "CloudFlare"
    # plugin (that needs its own cf-ray/cookie signals) -- the vendor identity is hiding inside a
    # different plugin's bracketed VALUE, not its own plugin name.
    ctx = _make_ctx()
    result = {
        "status": "ok",
        "used_arguments": {"target": "https://example.com"},
        "parsed": {"technologies": ["HTTPServer[cloudflare]", "jQuery[1.8.2]"]},
    }
    _merge_protection_detection(ctx, _tool("whatweb"), result, {"target": "https://example.com"})
    assert ctx.session["recon_result"]["protections"]["https://example.com"] == [
        "cloudflare (WAF/CDN, whatweb, via HTTPServer)"
    ]


def test_whatweb_label_carries_certainty_when_the_parsed_result_has_it():
    # agent/tools/builders/whatweb.py's own parse_whatweb_output (JSON-Verbose) sets this
    # alongside "technologies" -- when present, the label should surface it, not silently drop it.
    ctx = _make_ctx()
    result = {
        "status": "ok",
        "used_arguments": {"target": "https://example.com"},
        "parsed": {
            "technologies": ["CloudFlare[nginx]"],
            "technology_certainty": {"CloudFlare": 100},
        },
    }
    _merge_protection_detection(ctx, _tool("whatweb"), result, {"target": "https://example.com"})
    assert ctx.session["recon_result"]["protections"]["https://example.com"] == [
        "CloudFlare (WAF/CDN, whatweb, 100% certainty)"
    ]


def test_whatweb_label_omits_certainty_when_the_parsed_result_has_none():
    # Backward compatible with a "parsed" shape that predates technology_certainty entirely --
    # never claims a confidence figure that was never actually reported.
    ctx = _make_ctx()
    result = {
        "status": "ok",
        "used_arguments": {"target": "https://example.com"},
        "parsed": {"technologies": ["CloudFlare[nginx]"]},
    }
    _merge_protection_detection(ctx, _tool("whatweb"), result, {"target": "https://example.com"})
    assert ctx.session["recon_result"]["protections"]["https://example.com"] == [
        "CloudFlare (WAF/CDN, whatweb)"
    ]


def test_whatweb_with_no_known_waf_tokens_is_a_no_op():
    ctx = _make_ctx()
    result = {
        "status": "ok",
        "used_arguments": {"target": "https://example.com"},
        "parsed": {"technologies": ["jQuery[1.8.2]", "HTTPServer[Apache/2.4.41]"]},
    }
    _merge_protection_detection(ctx, _tool("whatweb"), result, {"target": "https://example.com"})
    assert ctx.session.get("recon_result", {}).get("protections", {}) == {}


def test_failed_result_is_a_no_op():
    ctx = _make_ctx()
    result = {"status": "error", "error": "boom"}
    _merge_protection_detection(ctx, _tool("nuclei"), result, {"target": "https://example.com"})
    assert ctx.session.get("recon_result", {}).get("protections", {}) == {}


def test_repeated_detection_does_not_duplicate_the_same_label():
    ctx = _make_ctx()
    result = {
        "status": "ok",
        "used_arguments": {"target": "https://example.com"},
        "parsed": [{"template_id": "global-waf-detect", "name": "Global WAF Detect Matchers", "matcher_name": "cloudflare"}],
    }
    _merge_protection_detection(ctx, _tool("nuclei"), result, {"target": "https://example.com"})
    _merge_protection_detection(ctx, _tool("nuclei"), result, {"target": "https://example.com"})
    assert ctx.session["recon_result"]["protections"]["https://example.com"] == [
        "cloudflare (WAF, nuclei global-waf-detect)"
    ]


def test_addendum_empty_when_nothing_detected():
    assert _protection_task_addendum({}) == ""
    assert _protection_task_addendum({"recon_result": {"protections": {}}}) == ""


def test_addendum_lists_known_protections_and_gives_behavioral_guidance():
    session = {"recon_result": {"protections": {"https://example.com": ["cloudflare (WAF, nuclei global-waf-detect)"]}}}
    addendum = _protection_task_addendum(session)
    assert "https://example.com: cloudflare (WAF, nuclei global-waf-detect)" in addendum
    assert "lower-aggression" in addendum
    assert "advisory_note" in addendum
