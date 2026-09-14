"""Cyrillic-script domains/URLs (e.g. банк.рф) are a real target/scope shape some bug-bounty
programs actually use -- agent/tools/builders/validators.py's shape checks used to reject them
outright with no way around it, both server-side and in the New Project form's own client-side chip
preview (templates/partials/new_project_form.html, covered separately by JS-level reasoning, not
here). to_ascii_hostname() covers the other half: an accepted Cyrillic domain must still actually
resolve once a real tool call is made (see tests/test_dns_lookup.py's own Cyrillic coverage).
"""
import pytest

from agent.tools.builders.validators import to_ascii_hostname, validate_scope_entry, validate_target


def test_validate_target_accepts_a_plain_cyrillic_domain():
    assert validate_target("банк.рф") == "банк.рф"


def test_validate_target_accepts_a_cyrillic_domain_inside_a_url():
    assert validate_target("https://банк.рф/path?x=1") == "https://банк.рф/path?x=1"


def test_validate_target_accepts_a_mixed_cyrillic_ascii_domain():
    assert validate_target("тест-prod.example.com") == "тест-prod.example.com"


def test_validate_target_still_rejects_shell_injection_shapes():
    with pytest.raises(ValueError):
        validate_target("банк.рф; rm -rf /")


def test_validate_scope_entry_accepts_a_cyrillic_wildcard():
    assert validate_scope_entry("*.банк.рф") == "*.банк.рф"


def test_validate_scope_entry_accepts_a_scheme_prefixed_cyrillic_wildcard():
    assert validate_scope_entry("https://*.банк.рф") == "*.банк.рф"


# --- to_ascii_hostname(): the punycode conversion real DNS resolution (socket.getaddrinfo, glibc)
# actually needs -- see test_dns_lookup.py for the end-to-end confirmation this matters, not just a
# shape-check nicety.


def test_to_ascii_hostname_converts_a_real_cyrillic_domain():
    assert to_ascii_hostname("яндекс.рф") == "xn--d1acpjx3f.xn--p1ai"


def test_to_ascii_hostname_leaves_ascii_domains_unchanged():
    assert to_ascii_hostname("example.com") == "example.com"


def test_to_ascii_hostname_falls_back_to_the_original_on_a_malformed_label():
    # An empty label (a stray double dot, e.g. a copy-paste typo) makes the stdlib "idna" codec
    # itself raise UnicodeError -- must not propagate that here, just hand back the original string
    # so the real getaddrinfo() call produces its own ordinary resolution error instead of a
    # confusing UnicodeError on top of it.
    malformed = "банк..рф"
    assert to_ascii_hostname(malformed) == malformed
