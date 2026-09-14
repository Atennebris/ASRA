"""agent/tools/passive_detectors.py -- deterministic, signature-based passive checks, moved out of
agent/tools/native.py so agent/tools/toolkit_store.py can reuse them without a circular import (see
that module's own docstring). Behavior must stay identical to before the move -- these tests cover
the four detectors directly; tests/test_native_http_request_detectors.py covers native.py's own
http_request still wiring them correctly end-to-end after the extraction."""
from agent.tools.passive_detectors import (
    detect_command_injection,
    detect_flags,
    detect_open_redirect,
    detect_reflected_payload,
    detect_sql_error,
)


# --- detect_reflected_payload --------------------------------------------------------------------


def test_reflected_payload_detects_unescaped_query_value_in_body():
    url = "https://example.com/search?q=<script>alert(1)</script>"
    body = "results for <script>alert(1)</script>"
    hit = detect_reflected_payload(url, body)
    assert hit == {"param": "q", "value": "<script>alert(1)</script>"}


def test_reflected_payload_ignores_short_or_benign_values():
    assert detect_reflected_payload("https://example.com/search?q=abc", "abc") is None
    assert detect_reflected_payload("https://example.com/search?q=<a", "<a") is None  # < 4 chars


def test_reflected_payload_requires_the_value_to_actually_appear_in_body():
    url = "https://example.com/search?q=<script>x</script>"
    assert detect_reflected_payload(url, "no reflection here") is None


# --- detect_sql_error -----------------------------------------------------------------------------


def test_sql_error_requires_a_quote_shaped_probe_in_the_url():
    body = "You have an error in your SQL syntax"
    assert detect_sql_error("https://example.com/item?id=1", body) is None  # no quote probe
    hit = detect_sql_error("https://example.com/item?id=1'", body)
    assert hit == {"engine": "mysql", "matched": "You have an error in your SQL syntax"}


def test_sql_error_matches_multiple_engines():
    # Real Oracle error text is always emitted as "ORA-NNNNN" uppercase -- re.IGNORECASE (fixed
    # after review, was missing on this one pattern) so it actually matches real output.
    assert detect_sql_error("https://example.com/x?id='", "ORA-00933: bad SQL")["engine"] == "oracle"
    assert detect_sql_error("https://example.com/x?id='", "ora-00933: bad sql")["engine"] == "oracle"
    assert detect_sql_error("https://example.com/x?id='", "unrecognized text") is None


# --- detect_command_injection ----------------------------------------------------------------------


def test_command_injection_requires_an_injection_shaped_probe_in_the_url():
    body = "root:x:0:0:root:/root:/bin/bash"
    assert detect_command_injection("https://example.com/x?f=safe", body) is None
    hit = detect_command_injection("https://example.com/x?f=../etc/passwd", body)
    assert hit == {"signature": "etc_passwd", "matched": "root:x:0:0:"}


def test_command_injection_shell_output_signature():
    body = "uid=0(root) gid=0(root) groups=0(root)"
    hit = detect_command_injection("https://example.com/x?cmd=;id", body)
    assert hit["signature"] == "shell_id_output"


# --- detect_open_redirect -------------------------------------------------------------------------


def test_open_redirect_matches_a_hop_whose_location_equals_the_param_value():
    url = "https://example.com/go?redirect=https://evil.example"
    hit = detect_open_redirect(url, [(302, {"location": "https://evil.example"})])
    assert hit == {"param": "redirect", "value": "https://evil.example", "location": "https://evil.example"}


def test_open_redirect_ignores_non_redirect_param_names():
    url = "https://example.com/go?q=https://evil.example"
    assert detect_open_redirect(url, [(302, {"location": "https://evil.example"})]) is None


def test_open_redirect_no_hops_means_no_hit():
    url = "https://example.com/go?redirect=https://evil.example"
    assert detect_open_redirect(url, []) is None


def test_open_redirect_location_header_lookup_is_case_insensitive_key():
    url = "https://example.com/go?next=https://evil.example"
    hit = detect_open_redirect(url, [(301, {"Location": "https://evil.example"})])
    assert hit is not None


# --- detect_flags (toolkit_store's own aggregate entry point) -------------------------------------


def test_detect_flags_aggregates_every_detector_hit():
    url = "https://example.com/search?q=<script>x</script>&id=1'"
    body = "reflects <script>x</script> and: you have an error in your sql syntax"
    flags = detect_flags(url, 200, {}, body)
    assert set(flags) == {"reflected_payload", "sql_error"}


def test_detect_flags_open_redirect_from_a_single_3xx_response():
    url = "https://example.com/go?redirect=https://evil.example"
    flags = detect_flags(url, 302, {"location": "https://evil.example"}, "")
    assert flags == ["open_redirect"]


def test_detect_flags_empty_for_a_clean_response():
    assert detect_flags("https://example.com/", 200, {}, "<html>hello</html>") == []


def test_detect_flags_handles_none_status():
    assert detect_flags("https://example.com/", None, {}, "") == []
