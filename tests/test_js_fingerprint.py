"""Client-side (JS/DOM-executed) technology fingerprinting: agent/tools/js_fingerprint.py's
signature loading/probe-script building/run_js_fingerprint (mocked at the BrowserSessionManager
boundary, same project-wide convention as tests/test_browser_tools.py -- never drives a real
Chromium), agent/core.py's _merge_technology_details (folds a detection list into recon_result the
same deterministic, code-driven way _merge_protection_detection already does), and the new third
source _confirmed_versions_for_product reads so a client-confirmed version actually grounds
cve_lookup even when the model never transcribes it into record_target itself.
"""
import asyncio

import agent.tools.js_fingerprint as js_fingerprint
from agent.core import RunContext, _confirmed_versions_for_product, _merge_technology_details
from agent.tools.js_fingerprint import build_probe_script, load_signatures, run_js_fingerprint


def _run(coro):
    return asyncio.run(coro)


def _make_ctx(session: dict | None = None) -> RunContext:
    return RunContext(llm=None, session=session or {}, session_id="usr_test123")


# --- signature loading / probe-script building (pure, no browser) ---------------------------


def test_load_signatures_returns_a_nonempty_list_with_the_required_fields():
    signatures = load_signatures()
    assert signatures, "js_signatures.json must ship with at least one real signature"
    for sig in signatures:
        assert sig["name"]
        assert "detect_expr" in sig
        assert "version_expr" in sig
        assert isinstance(sig.get("base_confidence"), int)


def test_load_signatures_includes_jquery_with_a_runtime_global_check():
    names = {sig["name"] for sig in load_signatures()}
    assert "jQuery" in names


def test_build_probe_script_is_a_self_contained_iife_embedding_every_signature_name():
    signatures = load_signatures()
    script = build_probe_script(signatures)
    assert script.startswith("(function()")
    assert script.rstrip().endswith("})()")
    for sig in signatures:
        assert sig["name"] in script


def test_build_probe_script_wraps_each_detect_expr_so_one_bad_signature_cant_break_the_rest():
    signatures = [
        {"name": "Broken", "categories": [], "base_confidence": 50, "detect_expr": "throw new Error('x')", "version_expr": "null"},
        {"name": "jQuery", "categories": ["JavaScript library"], "base_confidence": 97, "detect_expr": "!!window.jQuery", "version_expr": "null"},
    ]
    script = build_probe_script(signatures)
    # Each call site is its own try/catch inside tryDetect -- one throwing detect_expr must not
    # prevent the next signature's own call from appearing/running (1 function def + 2 call sites).
    assert script.count("tryDetect(") == 3
    assert 'tryDetect("Broken"' in script
    assert 'tryDetect("jQuery"' in script


# --- run_js_fingerprint: mocked at the BrowserSessionManager boundary, no real Chromium ------


class _FakeManager:
    def __init__(self, eval_result=None, navigate_status="ok", evaluate_status="ok"):
        self._eval_result = eval_result if eval_result is not None else []
        self._navigate_status = navigate_status
        self._evaluate_status = evaluate_status
        self.navigated: list[tuple] = []
        self.evaluated: list[tuple] = []
        self.closed_sessions: list[str] = []

    async def navigate(self, session_id, url, wait_until, out_of_scope_entries):
        self.navigated.append((session_id, url, wait_until, out_of_scope_entries))
        return {"status": self._navigate_status, "error": "navigation failed" if self._navigate_status != "ok" else None}

    async def evaluate(self, session_id, expression, out_of_scope_entries):
        self.evaluated.append((session_id, expression, out_of_scope_entries))
        if self._evaluate_status != "ok":
            return {"status": self._evaluate_status, "error": "evaluate failed"}
        return {"status": "ok", "eval_result": self._eval_result}

    async def close_session(self, session_id):
        self.closed_sessions.append(session_id)


_DETECTIONS = [{"name": "jQuery", "categories": ["JavaScript library"], "confidence": 97, "version": "3.6.0"}]


def test_run_js_fingerprint_returns_detections_navigates_with_https_and_closes_the_context(monkeypatch):
    manager = _FakeManager(eval_result=_DETECTIONS)
    monkeypatch.setattr(js_fingerprint, "get_browser_manager", lambda: manager)
    monkeypatch.setattr(js_fingerprint, "_chromium_installed", lambda: True)
    monkeypatch.setenv("JS_FINGERPRINT_ENABLED", "true")

    result = _run(run_js_fingerprint("jsfp-usr_x-example.com", "example.com", ["evil.com"]))

    assert result == _DETECTIONS
    assert manager.navigated == [("jsfp-usr_x-example.com", "https://example.com", "domcontentloaded", ["evil.com"])]
    assert manager.evaluated[0][0] == "jsfp-usr_x-example.com"
    assert manager.closed_sessions == ["jsfp-usr_x-example.com"]


def test_run_js_fingerprint_does_not_add_a_scheme_when_one_is_already_present(monkeypatch):
    manager = _FakeManager(eval_result=[])
    monkeypatch.setattr(js_fingerprint, "get_browser_manager", lambda: manager)
    monkeypatch.setattr(js_fingerprint, "_chromium_installed", lambda: True)

    _run(run_js_fingerprint("jsfp-1", "https://example.com/", None))

    assert manager.navigated[0][1] == "https://example.com/"


def test_run_js_fingerprint_returns_empty_and_still_closes_when_navigate_fails(monkeypatch):
    manager = _FakeManager(navigate_status="error")
    monkeypatch.setattr(js_fingerprint, "get_browser_manager", lambda: manager)
    monkeypatch.setattr(js_fingerprint, "_chromium_installed", lambda: True)

    result = _run(run_js_fingerprint("jsfp-2", "example.com", None))

    assert result == []
    assert manager.closed_sessions == ["jsfp-2"]


def test_run_js_fingerprint_returns_empty_when_chromium_is_not_installed(monkeypatch):
    manager = _FakeManager(eval_result=_DETECTIONS)
    monkeypatch.setattr(js_fingerprint, "get_browser_manager", lambda: manager)
    monkeypatch.setattr(js_fingerprint, "_chromium_installed", lambda: False)

    result = _run(run_js_fingerprint("jsfp-3", "example.com", None))

    assert result == []
    assert manager.navigated == []  # never even attempted -- an explicit early return, not a caught exception


def test_run_js_fingerprint_skips_entirely_when_disabled_via_env(monkeypatch):
    manager = _FakeManager(eval_result=_DETECTIONS)
    monkeypatch.setattr(js_fingerprint, "get_browser_manager", lambda: manager)
    monkeypatch.setattr(js_fingerprint, "_chromium_installed", lambda: True)
    monkeypatch.setenv("JS_FINGERPRINT_ENABLED", "false")

    result = _run(run_js_fingerprint("jsfp-4", "example.com", None))

    assert result == []
    assert manager.navigated == []


# --- _merge_technology_details: folds detections into recon_result, same discipline as
#     _merge_protection_detection (tests/test_protection_detection.py) --------------------------


def test_merge_technology_details_is_a_noop_with_no_detections():
    ctx = _make_ctx()
    _merge_technology_details(ctx, "example.com", [])
    assert ctx.session.get("recon_result", {}).get("technology_details", {}) == {}


def test_merge_technology_details_synthesizes_a_flat_token_and_a_structured_detail():
    ctx = _make_ctx()
    _merge_technology_details(ctx, "example.com", _DETECTIONS)

    technologies = ctx.session["recon_result"]["technologies"]["example.com"]
    assert "jQuery[3.6.0]" in technologies

    details = ctx.session["recon_result"]["technology_details"]["example.com"]["jQuery"]
    assert details["version"] == "3.6.0"
    assert details["certainty"] == 97
    assert details["sources"] == ["js_dom"]
    assert details["categories"] == ["JavaScript library"]

    certainty = ctx.session["recon_result"]["technology_certainty"]["example.com"]["jQuery"]
    assert certainty == 97


def test_merge_technology_details_does_not_duplicate_an_existing_whatweb_token_and_marks_both_sources():
    ctx = _make_ctx({
        "recon_result": {
            "technologies": {"example.com": ["jQuery[3.6.0]"]},
            "technology_certainty": {"example.com": {"jQuery": 60}},
        },
    })
    _merge_technology_details(ctx, "example.com", _DETECTIONS)

    technologies = ctx.session["recon_result"]["technologies"]["example.com"]
    assert technologies.count("jQuery[3.6.0]") == 1  # no duplicate token appended

    details = ctx.session["recon_result"]["technology_details"]["example.com"]["jQuery"]
    assert sorted(details["sources"]) == ["js_dom", "whatweb"]
    # max(existing 60, new 97) -- never silently overwritten downward.
    assert ctx.session["recon_result"]["technology_certainty"]["example.com"]["jQuery"] == 97


def test_merge_technology_details_backfills_version_from_a_whatweb_token_when_js_dom_found_none():
    ctx = _make_ctx({"recon_result": {"technologies": {"example.com": ["nginx[1.18.0]"]}}})
    detections = [{"name": "nginx", "categories": [], "confidence": 55, "version": None}]

    _merge_technology_details(ctx, "example.com", detections)

    details = ctx.session["recon_result"]["technology_details"]["example.com"]["nginx"]
    assert details["version"] == "1.18.0"


# --- _confirmed_versions_for_product: technology_details as a third, deterministic source ----


def test_confirmed_versions_for_product_reads_a_high_certainty_technology_details_entry():
    session = {
        "recon_result": {
            "technology_details": {
                "example.com": {"WordPress": {"version": "6.4.2", "certainty": 96, "sources": ["js_dom"]}},
            },
        },
        "findings": [],
    }
    confirmed = _confirmed_versions_for_product(session, "WordPress")
    assert ("example.com", "6.4.2") in confirmed


def test_confirmed_versions_for_product_ignores_a_low_certainty_technology_details_entry():
    session = {
        "recon_result": {
            "technology_details": {
                "example.com": {"Laravel": {"version": "9.0", "certainty": 55, "sources": ["js_dom"]}},
            },
        },
        "findings": [],
    }
    confirmed = _confirmed_versions_for_product(session, "Laravel")
    assert confirmed == []
