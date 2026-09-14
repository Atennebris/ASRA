"""waf_evasion_probe: a small, FIXED matrix of payload/signature-level WAF-evasion mutations (see
agent/tools/waf_evasion.py's own module docstring for the real incident -- a real session, usr_136b4c --
that motivated this). Never drives a real target; mocked via httpx.MockTransport, same pattern
tests/test_http_request_retry.py already established for this exact class of test.
"""
import httpx

import agent.tools.waf_evasion as we
from agent.tools.waf_evasion import (
    _mut_alt_whitespace,
    _mut_case_randomize,
    _mut_double_url_encode,
    _mut_inline_comment_split,
    _mut_null_byte,
    _mut_padding_overflow,
    _mut_protocol_obfuscation,
    _mut_unicode_fullwidth,
    waf_evasion_probe,
)

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


# --- pure mutation functions -- no httpx needed at all ---------------------------------------


def test_double_url_encode_roundtrips_to_the_original_after_decoding_twice():
    from urllib.parse import unquote
    mutated = _mut_double_url_encode("<script>")
    assert unquote(unquote(mutated)) == "<script>"
    assert mutated != we._mut_baseline("<script>")  # genuinely different from a single encode


def test_unicode_fullwidth_substitutes_special_chars():
    mutated = _mut_unicode_fullwidth("<script>")
    assert "%EF%BC%9C" in mutated or "＜" in mutated  # fullwidth '<' (U+FF1C), percent-encoded


def test_case_randomize_alternates_case():
    mutated = _mut_case_randomize("script")
    from urllib.parse import unquote
    assert unquote(mutated) != "script"
    assert unquote(mutated).lower() == "script"


def test_inline_comment_split_breaks_up_long_words():
    from urllib.parse import unquote
    mutated = unquote(_mut_inline_comment_split("select"))
    assert "/**/" in mutated
    assert mutated.replace("/**/", "") == "select"


def test_alt_whitespace_replaces_encoded_space_with_tab():
    mutated = _mut_alt_whitespace("a b")
    assert "%09" in mutated
    assert "%20" not in mutated


def test_null_byte_insertion_appends_null_byte():
    assert _mut_null_byte("x").endswith("%00")


def test_padding_overflow_prepends_filler_before_the_payload(monkeypatch):
    from urllib.parse import unquote
    monkeypatch.setattr(we, "_PADDING_OVERFLOW_BYTES", 100)
    mutated = unquote(_mut_padding_overflow("<script>alert(1)</script>"))
    assert mutated == "A" * 100 + "<script>alert(1)</script>"


def test_padding_overflow_defaults_to_8192_bytes():
    from urllib.parse import unquote
    mutated = unquote(_mut_padding_overflow("x"))
    assert mutated == "A" * 8192 + "x"


def test_protocol_obfuscation_inserts_a_tab_into_the_javascript_scheme():
    from urllib.parse import unquote
    mutated = unquote(_mut_protocol_obfuscation("javascript:alert(1)"))
    assert mutated == "java\tscript:alert(1)"


def test_protocol_obfuscation_is_case_insensitive():
    from urllib.parse import unquote
    mutated = unquote(_mut_protocol_obfuscation("JavaScript:alert(1)"))
    assert mutated == "java\tscript:alert(1)"


def test_protocol_obfuscation_passes_through_a_payload_with_no_javascript_scheme():
    from urllib.parse import unquote
    assert unquote(_mut_protocol_obfuscation("<script>alert(1)</script>")) == "<script>alert(1)</script>"


# --- waf_evasion_probe itself, mocked transport -----------------------------------------------


def test_probe_sends_exactly_twelve_requests(monkeypatch):
    monkeypatch.setattr(we, "_REQUEST_DELAY_SECONDS", 0)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = waf_evasion_probe({"target": "https://example.com/search", "param_name": "q", "payload": "<script>alert(1)</script>"})

    assert result["status"] == "ok"
    assert len(calls) == 12  # 1 baseline + 8 payload mutations + pollution + alt-method + spoofed-ip


def test_probe_flags_a_mutation_that_bypasses_a_naive_blocklist(monkeypatch):
    """Mirrors a real naive WAF: blocks the literal (single-encoded) '<script>' substring in the
    query string, nothing smarter -- double-encoding and case-randomization should both slip past
    it, exactly the class of bypass this tool exists to surface."""
    monkeypatch.setattr(we, "_REQUEST_DELAY_SECONDS", 0)

    def handler(request):
        url = str(request.url)
        if request.method == "POST":
            blocked = "<script>" in request.content.decode(errors="ignore")
        else:
            blocked = "%3Cscript%3E" in url
        return httpx.Response(403, text="Attack detected") if blocked else httpx.Response(200, text="reflected")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = waf_evasion_probe({"target": "https://example.com/search", "param_name": "q", "payload": "<script>alert(1)</script>"})

    assert result["baseline"]["status_code"] == 403
    assert "double_url_encode" in result["candidate_bypasses"]
    assert "case_randomize" in result["candidate_bypasses"]


def test_probe_finds_no_bypasses_when_every_variant_is_blocked_identically(monkeypatch):
    monkeypatch.setattr(we, "_REQUEST_DELAY_SECONDS", 0)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda request: httpx.Response(403, text="blocked")))

    result = waf_evasion_probe({"target": "https://example.com/search", "param_name": "q", "payload": "<script>alert(1)</script>"})

    assert result["candidate_bypasses"] == []


def test_probe_reports_a_clean_error_when_the_baseline_request_itself_fails(monkeypatch):
    monkeypatch.setattr(we, "_REQUEST_DELAY_SECONDS", 0)

    def handler(request):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = waf_evasion_probe({"target": "https://example.com/search", "param_name": "q", "payload": "x"})

    assert result["status"] == "error"
    assert "baseline" in result["error"]


def test_probe_surfaces_a_reflected_payload_detector_hit_even_when_status_code_matches_baseline(monkeypatch):
    """Reuses agent/tools/passive_detectors.py's own detect_reflected_payload -- a response whose
    STATUS CODE matches the baseline but whose body genuinely reflects the payload back UNESCAPED
    is still flagged via the detector, not just a status-code diff (every response here is 200, so
    differs_from_baseline is False for all of them)."""
    monkeypatch.setattr(we, "_REQUEST_DELAY_SECONDS", 0)

    def handler(request):
        # detect_reflected_payload compares the DECODED query value (parse_qsl) against the
        # response body -- reflect the real, unescaped payload back so it matches.
        from urllib.parse import parse_qsl, urlsplit
        params = dict(parse_qsl(urlsplit(str(request.url)).query))
        return httpx.Response(200, text=f"echo: {params.get('q', '')}")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = waf_evasion_probe({"target": "https://example.com/search", "param_name": "q", "payload": "<xss_marker>"})

    assert result["status"] == "ok"
    assert result["baseline"].get("reflected_payload_detected") is not None


def test_probe_defaults_method_to_get_when_not_given(monkeypatch):
    monkeypatch.setattr(we, "_REQUEST_DELAY_SECONDS", 0)
    methods_seen = []

    def handler(request):
        methods_seen.append(request.method)
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    waf_evasion_probe({"target": "https://example.com/search", "param_name": "q", "payload": "x"})

    assert methods_seen[0] == "GET"  # the baseline request, first one sent
