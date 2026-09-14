"""dns_lookup (agent/tools/native.py): a genuine NXDOMAIN-shaped failure must never be reported as
a retryable "error" -- real, confirmed incident this fixes: legitimate subdomain-guessing against
a real target produced 66 of these in one 14-minute window (one subagent burned its entire 900s
budget this way), each costing a full LLM 1-Step-Retry correction round-trip for a failure no
corrected argument could ever fix (a nonexistent hostname never resolves regardless of what else
is sent). A real resolver-side hiccup (EAI_AGAIN, "Temporary failure in name resolution") is a
genuinely different case and must still go through the normal retryable "error" path.
"""
import socket

from agent.tools.native import dns_lookup


def test_dns_lookup_returns_ok_not_error_for_a_genuine_nxdomain(monkeypatch):
    def fake_getaddrinfo(domain, port):
        exc = socket.gaierror("Name or service not known")
        exc.errno = socket.EAI_NONAME
        raise exc

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    result = dns_lookup({"domain": "nonexistent.example.com"})

    assert result["status"] == "ok"  # not "error" -- must never trigger a 1-Step Retry
    assert result["ips"] == []
    assert result["resolved"] is False


def test_dns_lookup_returns_ok_not_error_for_eai_nodata(monkeypatch):
    # Real, confirmed incident: this environment's own resolver returns EAI_NODATA (errno -5,
    # "No address associated with hostname") for a genuine no-such-domain result just as often as
    # EAI_NONAME -- the original fix only ever checked EAI_NONAME, so a real negative result kept
    # going through the retryable "error" path, and in one real session the 1-Step Retry "fixed"
    # it by silently substituting an unrelated already-known-good domain instead.
    def fake_getaddrinfo(domain, port):
        exc = socket.gaierror("No address associated with hostname")
        exc.errno = socket.EAI_NODATA
        raise exc

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    result = dns_lookup({"domain": "nodata.example.com"})

    assert result["status"] == "ok"  # not "error" -- must never trigger a 1-Step Retry
    assert result["ips"] == []
    assert result["resolved"] is False


def test_dns_lookup_still_reports_a_real_error_for_a_transient_resolver_failure(monkeypatch):
    def fake_getaddrinfo(domain, port):
        exc = socket.gaierror("Temporary failure in name resolution")
        exc.errno = getattr(socket, "EAI_AGAIN", -3)
        raise exc

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    result = dns_lookup({"domain": "example.com"})

    assert result["status"] == "error"  # a genuinely different, still-worth-retrying case
    assert "error" in result


def test_dns_lookup_succeeds_normally(monkeypatch):
    def fake_getaddrinfo(domain, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    result = dns_lookup({"domain": "example.com"})

    assert result["status"] == "ok"
    assert result["ips"] == ["93.184.216.34"]
    assert result["resolved"] is True


def test_dns_lookup_converts_a_cyrillic_domain_to_punycode_before_resolving(monkeypatch):
    """Real incident this fix closes: socket.getaddrinfo() raises EAI_NONAME on a raw Cyrillic
    hostname even for a real, live domain -- glibc's resolver needs the wire-format ASCII/punycode
    label, not the Unicode display form. Confirmed live against a real domain (яндекс.рф) before
    this fix existed."""
    seen = {}

    def fake_getaddrinfo(domain, port):
        seen["domain"] = domain
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("213.180.204.242", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    result = dns_lookup({"domain": "яндекс.рф"})

    assert seen["domain"] == "xn--d1acpjx3f.xn--p1ai"  # the real resolver call got punycode, not raw Cyrillic
    assert result["status"] == "ok"
    assert result["resolved"] is True


def test_dns_lookup_negative_result_still_shows_the_original_cyrillic_domain(monkeypatch):
    def fake_getaddrinfo(domain, port):
        exc = socket.gaierror("Name or service not known")
        exc.errno = socket.EAI_NONAME
        raise exc

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    result = dns_lookup({"domain": "несуществующий-домен-asra-test.рф"})

    assert result["resolved"] is False
    assert "несуществующий-домен-asra-test.рф" in result["note"]  # operator-facing text stays in the form they typed
