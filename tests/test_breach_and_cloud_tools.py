"""New OSINT/exploit-tier tools adapted from real-world reference implementations found while
researching github.com/Viralmaniar's repositories:

- xposedornot_check / hibp_breach_check / hibp_password_check (agent/tools/native.py) -- breach-
  exposure lookups (XposedOrNot's free keyless API, Have I Been Pwned's paid breachedaccount API,
  and HIBP's free k-anonymity Pwned Passwords range API).
- cloud_bucket_scan (agent/tools/native.py) -- active anonymous read/write permission probe for an
  AWS S3 / GCS / Azure Blob bucket, adapted from CloudSpecter's technique.
- default_creds_check's new "vendor" param -- a small curated vendor-keyed default-credential table,
  adapted from Passhunt's idea (a much larger vendor/password database) at a scale appropriate here.
- favicon_hash's new "shodan_search_url" field -- closes the loop MurMurHash's own technique
  describes (compute the hash, then actually go hunt it on Shodan) that favicon_hash already half-
  implemented (it computed the hash but never built the follow-up query).

Same mocking convention as tests/test_otx_urlscan.py (a real httpx.Client backed by
httpx.MockTransport, cache isolated via monkeypatch).
"""
import httpx

from agent.tools import native
from agent.tools.native import (
    cloud_bucket_scan,
    default_creds_check,
    favicon_hash,
    hibp_breach_check,
    hibp_password_check,
    xposedornot_check,
)
from agent.tools.tool_api_keys import TOOL_API_KEY_SPECS

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def _isolate_cache(monkeypatch):
    monkeypatch.setattr(native, "cache_get", lambda *a: None)
    monkeypatch.setattr(native, "cache_set", lambda *a: None)


# --- registration ------------------------------------------------------------------------------


def test_new_tools_are_registered():
    import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
    from agent.tools.registry import get_tool

    for name in ("xposedornot_check", "hibp_breach_check", "hibp_password_check"):
        spec = get_tool(name)
        assert spec is not None, name
        assert spec.category == "recon"
        assert spec.requires_allowed_target is False

    bucket_spec = get_tool("cloud_bucket_scan")
    assert bucket_spec is not None
    assert bucket_spec.category == "exploit"
    assert bucket_spec.requires_allowed_target is True


def test_hibp_breach_check_is_a_registered_tool_api_key_spec():
    assert TOOL_API_KEY_SPECS["hibp_breach_check"].env_var == "HIBP_API_KEY"


# --- xposedornot_check ---------------------------------------------------------------------------


def test_xposedornot_check_reports_a_real_exposure(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(
        lambda r: httpx.Response(200, json={"breaches": [["Tesco", "Vermillion"]], "email": "person@example.com", "status": "success"})
    ))

    result = xposedornot_check({"email": "person@example.com"})

    assert result["status"] == "ok"
    assert result["exposed"] is True
    assert result["breaches"] == ["Tesco", "Vermillion"]


def test_xposedornot_check_handles_a_clean_email_via_404(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda r: httpx.Response(404, json={"Error": "Not found", "email": None})))

    result = xposedornot_check({"email": "clean@example.com"})

    assert result == {"status": "ok", "email": "clean@example.com", "exposed": False, "breaches": []}


def test_xposedornot_check_handles_a_clean_email_via_200_error_body(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda r: httpx.Response(200, json={"Error": "Not found", "email": None})))

    result = xposedornot_check({"email": "clean@example.com"})

    assert result["status"] == "ok"
    assert result["exposed"] is False


def test_xposedornot_check_reports_rate_limiting_clearly(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda r: httpx.Response(429)))

    result = xposedornot_check({"email": "person@example.com"})

    assert result["status"] == "error"
    assert "rate limit" in result["error"].lower()


# --- hibp_breach_check ---------------------------------------------------------------------------


def test_hibp_breach_check_errors_clearly_without_a_key(monkeypatch):
    _isolate_cache(monkeypatch)
    result = hibp_breach_check({"email": "person@example.com"})
    assert result["status"] == "error"
    assert "HIBP_API_KEY" in result["error"]


def test_hibp_breach_check_parses_real_breaches_and_sends_the_key(monkeypatch):
    _isolate_cache(monkeypatch)
    seen_headers = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(dict(request.headers))
        return httpx.Response(200, json=[{
            "Name": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04",
            "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True,
        }])

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = hibp_breach_check({"email": "person@example.com", "_api_key": "test-hibp-key"})

    assert result["status"] == "ok"
    assert result["exposed"] is True
    assert result["breaches"] == [{
        "name": "Adobe", "domain": "adobe.com", "breach_date": "2013-10-04",
        "data_classes": ["Email addresses", "Passwords"], "is_verified": True,
    }]
    assert seen_headers[0]["hibp-api-key"] == "test-hibp-key"


def test_hibp_breach_check_handles_a_clean_email(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda r: httpx.Response(404)))

    result = hibp_breach_check({"email": "clean@example.com", "_api_key": "test-key"})

    assert result == {"status": "ok", "email": "clean@example.com", "exposed": False, "breaches": []}


def test_hibp_breach_check_reports_a_rejected_key_clearly(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda r: httpx.Response(401)))

    result = hibp_breach_check({"email": "person@example.com", "_api_key": "bad-key"})

    assert result["status"] == "error"
    assert "401" in result["error"]


# --- hibp_password_check --------------------------------------------------------------------------


def test_hibp_password_check_detects_a_known_breached_password(monkeypatch):
    _isolate_cache(monkeypatch)
    # SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8 -- prefix 5BAA6, suffix below.
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(
        lambda r: httpx.Response(200, text="1E4C9B93F3F0682250B6CF8331B7EE68FD8:3730471\nAAAA:1")
    ))

    result = hibp_password_check({"password": "password"})

    assert result == {"status": "ok", "pwned": True, "times_seen": 3730471}


def test_hibp_password_check_reports_a_clean_password(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda r: httpx.Response(200, text="AAAA:1\nBBBB:2")))

    result = hibp_password_check({"password": "a genuinely unique passphrase 9x7q"})

    assert result == {"status": "ok", "pwned": False, "times_seen": 0}


def test_hibp_password_check_never_echoes_the_password(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda r: httpx.Response(200, text="AAAA:1")))

    result = hibp_password_check({"password": "hunter2"})

    assert "hunter2" not in str(result)
    assert "password" not in result


def test_hibp_password_check_only_sends_the_hash_prefix(monkeypatch):
    _isolate_cache(monkeypatch)
    seen_paths = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_paths.append(request.url.path)
        return httpx.Response(200, text="AAAA:1")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    hibp_password_check({"password": "password"})

    assert seen_paths == ["/range/5BAA6"]  # only 5 hex chars, never the full hash or password


# --- default_creds_check vendor param (backed by cirt.net's harvested database) -------------------


def _mock_cirt_database(monkeypatch, database: dict):
    """_load_cirt_default_passwords is @functools.lru_cache'd -- replacing the module-level name
    itself (rather than trying to clear/pre-seed the cache) is what agent/tools/native.py's own
    _resolve_vendor_credential_pairs actually looks up at call time."""
    monkeypatch.setattr(native, "_load_cirt_default_passwords", lambda: database)


def _post_body_attempts(monkeypatch):
    attempted = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json
        body = _json.loads(request.content)
        attempted.append((body["email"], body["password"]))
        return httpx.Response(403)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    return attempted


def test_default_creds_check_rejects_an_unknown_vendor_with_a_spelling_hint(monkeypatch):
    _mock_cirt_database(monkeypatch, {"Hikvision": [{"user": "admin", "password": "12345"}]})

    result = default_creds_check({"target": "https://example.com/login", "vendor": "not-a-real-vendor"})

    assert result["status"] == "error"
    assert "not-a-real-vendor" in result["error"]
    assert "spelling" in result["error"]


def test_default_creds_check_reports_a_helpful_hint_when_the_database_was_never_harvested(monkeypatch):
    _mock_cirt_database(monkeypatch, {})

    result = default_creds_check({"target": "https://example.com/login", "vendor": "hikvision"})

    assert result["status"] == "error"
    assert "harvest_cirt_default_passwords.py" in result["error"]


def test_default_creds_check_matches_case_and_punctuation_insensitively(monkeypatch):
    _mock_cirt_database(monkeypatch, {"Hikvision": [{"user": "admin", "password": "12345"}]})
    attempted = _post_body_attempts(monkeypatch)

    result = default_creds_check({"target": "https://example.com/login", "vendor": "  HIK-vision "})

    assert result["status"] == "ok"
    assert result["vendor"] == "Hikvision"  # the real cirt.net name, not the raw query
    assert attempted[0] == ("admin", "12345")


def test_default_creds_check_never_raw_substring_matches_a_short_unrelated_vendor(monkeypatch):
    """Real, confirmed incident: querying vendor="elasticsearch" raw-substring-matched the totally
    unrelated real vendor "AST" (normalized "ast" sits inside "el-AST-icsearch") and would have
    silently tried AST's own passwords against an Elasticsearch target. Short vendor names must only
    match via an exact or whole-word hit, never a bare substring check."""
    _mock_cirt_database(monkeypatch, {"AST": [{"user": "ast-admin", "password": "ast-pass"}]})

    result = default_creds_check({"target": "https://example.com/login", "vendor": "elasticsearch"})

    assert result["status"] == "error"  # correctly MISSING, not a false match onto "AST"


def test_default_creds_check_matches_a_whole_word_in_a_longer_query(monkeypatch):
    _mock_cirt_database(monkeypatch, {"HP": [{"user": "admin", "password": "admin"}]})
    attempted = _post_body_attempts(monkeypatch)

    result = default_creds_check({"target": "https://example.com/login", "vendor": "hp printer"})

    assert result["status"] == "ok"
    assert result["vendor"] == "HP"
    assert attempted[0] == ("admin", "admin")


def test_default_creds_check_tries_vendor_pairs_first_then_the_generic_list(monkeypatch):
    _mock_cirt_database(monkeypatch, {"Hikvision": [{"user": "admin", "password": "12345"}]})
    attempted = _post_body_attempts(monkeypatch)

    result = default_creds_check({"target": "https://example.com/login", "vendor": "hikvision"})

    assert result["status"] == "ok"
    assert attempted[0] == ("admin", "12345")  # vendor pair tried before the generic list
    assert ("admin", "admin") in attempted  # generic list still tried after
    assert result["attempted"] == 1 + len(native._DEFAULT_CREDENTIAL_PAIRS)


def test_default_creds_check_normalizes_none_and_drops_fully_blank_entries(monkeypatch):
    _mock_cirt_database(monkeypatch, {"2Wire, Inc.": [
        {"user": "http", "password": "(none)"},
        {"user": "(none)", "password": "(none)"},  # nothing to actually submit -- dropped
    ]})
    attempted = _post_body_attempts(monkeypatch)

    result = default_creds_check({"target": "https://example.com/login", "vendor": "2wire"})

    assert result["status"] == "ok"
    assert attempted[0] == ("http", "")
    assert result["attempted"] == 1 + len(native._DEFAULT_CREDENTIAL_PAIRS)


def test_default_creds_check_unchanged_without_a_vendor(monkeypatch):
    attempted = _post_body_attempts(monkeypatch)

    result = default_creds_check({"target": "https://example.com/login"})

    assert result["attempted"] == 6
    assert result["vendor"] is None
    assert attempted[0] == ("admin", "admin")


# --- cloud_bucket_scan ---------------------------------------------------------------------------


def test_cloud_bucket_scan_rejects_an_unrecognized_host():
    result = cloud_bucket_scan({"target": "https://example.com/not-a-bucket"})
    assert result["status"] == "error"
    assert "s3.amazonaws.com" in result["error"] or "isn't a recognized" in result["error"]


def test_cloud_bucket_scan_reports_high_severity_for_a_public_readable_bucket(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<ListBucketResult><Name>cisrc</Name></ListBucketResult>")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = cloud_bucket_scan({"target": "https://cisrc.s3.amazonaws.com"})

    assert result["status"] == "ok"
    assert result["provider"] == "aws"
    assert result["readable"] is True
    assert result["severity"] == "HIGH"


def test_cloud_bucket_scan_reports_critical_severity_for_anonymous_write_and_cleans_up(monkeypatch):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if request.method == "GET":
            return httpx.Response(200, text="<ListBucketResult></ListBucketResult>")
        if request.method == "PUT":
            return httpx.Response(200)
        if request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(500)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = cloud_bucket_scan({"target": "https://cisrc.s3.amazonaws.com", "test_write": True})

    assert result["severity"] == "CRITICAL"
    assert result["writable"] is True
    assert result["cleanup_ok"] is True
    assert calls == ["GET", "PUT", "DELETE"]  # write-test object was actually cleaned up


def test_cloud_bucket_scan_reports_info_severity_for_a_private_bucket(monkeypatch):
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda r: httpx.Response(403)))

    result = cloud_bucket_scan({"target": "https://private-bucket.s3.amazonaws.com"})

    assert result["readable"] is False
    assert result["severity"] == "INFO"


def test_cloud_bucket_scan_handles_gcs(monkeypatch):
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(
        lambda r: httpx.Response(200, text="<ListBucketResult></ListBucketResult>")
    ))

    result = cloud_bucket_scan({"target": "https://storage.googleapis.com/my-public-gcs-bucket"})

    assert result["provider"] == "gcp"
    assert result["readable"] is True


def test_cloud_bucket_scan_never_tests_anonymous_write_on_azure(monkeypatch):
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(
        lambda r: httpx.Response(200, text="<EnumerationResults></EnumerationResults>")
    ))

    result = cloud_bucket_scan({"target": "https://myaccount.blob.core.windows.net/mycontainer", "test_write": True})

    assert result["provider"] == "azure"
    assert result["readable"] is True
    assert result["writable"] is False
    assert "platform level" in result["write_note"]


# --- favicon_hash's new shodan_search_url field ---------------------------------------------------


def test_favicon_hash_includes_a_ready_shodan_search_url(monkeypatch):
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda r: httpx.Response(200, content=b"\x00\x01\x02fake-favicon-bytes")))

    result = favicon_hash({"target": "https://example.com"})

    assert result["status"] == "ok"
    assert result["favicon_found"] is True
    assert result["shodan_search_url"] == f"https://www.shodan.io/search?query=http.favicon.hash%3A{result['mmh3_hash']}"
