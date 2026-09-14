"""interpret_ssl_cert_info_failure -- a TLS handshake failure against a bare IP address that's
actually a CDN/proxy edge (Cloudflare and similar) is deterministic, not transient: the proxy relies
on SNI (the hostname a client connects as) to route to the right certificate/origin, and a bare IP
offers no meaningful SNI value. Real incident this fixes: two separate ssl_cert_info calls against
the same Cloudflare edge IP both failed identically with SSLV3_ALERT_HANDSHAKE_FAILURE, and the raw
OpenSSL error text gave the model no hint that retrying the same IP could never work.
"""
from agent.tools.native import interpret_ssl_cert_info_failure


def test_hint_fires_for_a_bare_ip_handshake_failure():
    result = {
        "status": "error",
        "error": "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure (_ssl.c:1000)",
        "target": "104.21.65.240",
    }
    hint = interpret_ssl_cert_info_failure(result)
    assert hint is not None
    assert "104.21.65.240" in hint
    assert "SNI" in hint


def test_hint_is_none_for_a_real_hostname_target():
    result = {
        "status": "error",
        "error": "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure (_ssl.c:1000)",
        "target": "example.com",
    }
    assert interpret_ssl_cert_info_failure(result) is None


def test_hint_is_none_for_an_unrelated_error():
    result = {"status": "error", "error": "timed out", "target": "104.21.65.240"}
    assert interpret_ssl_cert_info_failure(result) is None


def test_hint_is_none_for_a_successful_result():
    result = {"status": "ok", "target": "104.21.65.240"}
    assert interpret_ssl_cert_info_failure(result) is None
