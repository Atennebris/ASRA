"""whois_lookup (agent/tools/native.py): follows the standard IANA -> registry -> registrar
referral chain a real whois client walks. Real incident this covers: a live recon pass against an
.io domain (a thin, gTLD-style registry) got nothing but a registry-level stub — "registrant
details unavailable" — because the code used to stop after the first (IANA -> registry) hop and
never followed the registry's OWN referral to the actual registrar's whois server, one hop further.
"""
from unittest import mock

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools.native import whois_lookup


def _query(responses):
    return lambda server, query, timeout=10.0: responses[(server, query)]


def test_whois_lookup_follows_iana_referral_to_the_registry():
    responses = {
        ("whois.iana.org", "com"): "refer:        whois.verisign-grs.com\n",
        ("whois.verisign-grs.com", "example.com"): "Domain Name: EXAMPLE.COM\nRegistrar: Some Registrar\n",
    }
    with mock.patch("agent.tools.native._whois_query", side_effect=_query(responses)):
        result = whois_lookup({"domain": "example.com"})
    assert result["status"] == "ok"
    assert result["server"] == "whois.verisign-grs.com"
    assert "EXAMPLE.COM" in result["raw"]


def test_whois_lookup_follows_a_second_registrar_referral_for_thin_gtld_registries():
    """Real incident: *.vimla.io only ever got whois.nic.io's own thin stub — the actual
    registrant data sits behind ITS OWN "Registrar WHOIS Server:" referral, one hop further."""
    responses = {
        ("whois.iana.org", "io"): "refer:        whois.nic.io\n",
        ("whois.nic.io", "vimla.io"): "Domain Name: vimla.io\nRegistrar WHOIS Server: whois.registrar-example.com\n",
        ("whois.registrar-example.com", "vimla.io"): "Domain Name: vimla.io\nRegistrant Name: Real Registrant Inc\n",
    }
    with mock.patch("agent.tools.native._whois_query", side_effect=_query(responses)):
        result = whois_lookup({"domain": "vimla.io"})
    assert result["status"] == "ok"
    assert result["server"] == "whois.registrar-example.com"
    assert "Real Registrant Inc" in result["raw"]


def test_whois_lookup_stops_cleanly_when_a_thick_registry_has_no_further_referral():
    """A thick ccTLD registry (whois.iis.se-shaped) already returns the final answer — attempting
    the second hop must be a safe no-op, not an error, when there's simply nothing to follow."""
    responses = {
        ("whois.iana.org", "se"): "refer:        whois.iis.se\n",
        ("whois.iis.se", "example.se"): "domain: example.se\nstatus: active\nregistrant: REDACTED FOR PRIVACY\n",
    }
    with mock.patch("agent.tools.native._whois_query", side_effect=_query(responses)):
        result = whois_lookup({"domain": "example.se"})
    assert result["status"] == "ok"
    assert result["server"] == "whois.iis.se"  # never moved past the registry — nothing to follow


def test_whois_lookup_never_loops_forever_on_a_referral_cycle():
    """A malformed/cyclical referral (points back at a server already visited) must terminate
    instead of looping — the seen_servers check is the backstop, _WHOIS_MAX_REGISTRAR_HOPS a second."""
    responses = {
        ("whois.iana.org", "io"): "refer:        whois.nic.io\n",
        ("whois.nic.io", "loop.io"): "Registrar WHOIS Server: whois.nic.io\n",  # points at itself
    }
    with mock.patch("agent.tools.native._whois_query", side_effect=_query(responses)):
        result = whois_lookup({"domain": "loop.io"})
    assert result["status"] == "ok"
    assert result["server"] == "whois.nic.io"


def test_whois_lookup_returns_error_on_socket_failure():
    with mock.patch("agent.tools.native._whois_query", side_effect=OSError("connection refused")):
        result = whois_lookup({"domain": "example.com"})
    assert result["status"] == "error"
    assert "connection refused" in result["error"]
