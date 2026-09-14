"""CIDR blocks ("10.0.0.0/24") and explicit "start - end" IP ranges ("192.168.1.1 - 192.168.1.254",
a common bug-bounty scope-table format for an address pool) as Target(s)/Out-of-scope entries.

Before this, validate_scope_entry's shape check didn't reject either format outright (digits/dots/
slashes were already legal characters), but allowed_targets.py's _matches_scope_entries only ever
did exact-hostname or "*.domain"-suffix matching -- a CIDR/range entry sat as an inert literal
string that could never actually match any real discovered IP inside it, in either direction
(exploitation allowlist or out-of-scope exclusion). The New Project form's own help text didn't
even claim to support either format ("URL, domain, host, IPv4, or IPv6").
"""
import ipaddress

import pytest

from agent.tools.allowed_targets import (
    extract_hostname,
    is_target_allowed,
    is_target_out_of_scope,
    parse_ip_range_or_cidr,
)
from agent.tools.builders.validators import validate_scope_entry
from agent.tools import allowed_targets


@pytest.fixture(autouse=True)
def _isolated_allowlist(tmp_path, monkeypatch):
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")


# --- extract_hostname: bare IPv6 literal, a real pre-existing bug this work exposed ---


def test_extract_hostname_handles_a_bare_unbracketed_ipv6_literal():
    """Real bug found while adding IPv6 CIDR support: urlparse("2001:db8::1") misreads "2001" as
    a URL scheme (no "//" or brackets to disambiguate), silently returning the wrong hostname."""
    assert extract_hostname("2001:db8::1") == "2001:db8::1"


def test_extract_hostname_still_handles_a_bracketed_ipv6_url():
    assert extract_hostname("http://[2001:db8::1]:8080/") == "2001:db8::1"


def test_extract_hostname_still_handles_a_bare_ipv4():
    assert extract_hostname("10.0.0.5") == "10.0.0.5"


# --- parse_ip_range_or_cidr: pure parsing/canonicalization ---


def test_parse_recognizes_a_plain_cidr_block():
    assert parse_ip_range_or_cidr("10.0.0.0/24") == "10.0.0.0/24"


def test_parse_canonicalizes_a_cidr_with_host_bits_set():
    """strict=False: a scope table sometimes writes the CIDR against a specific host inside the
    block rather than the network address itself -- still a real, intended CIDR entry."""
    assert parse_ip_range_or_cidr("10.0.0.5/24") == "10.0.0.0/24"


def test_parse_recognizes_a_range_with_spaces_around_the_dash():
    assert parse_ip_range_or_cidr("192.168.1.1 - 192.168.1.254") == "192.168.1.1-192.168.1.254"


def test_parse_recognizes_a_range_with_no_spaces():
    assert parse_ip_range_or_cidr("192.168.1.1-192.168.1.254") == "192.168.1.1-192.168.1.254"


def test_parse_rejects_a_range_where_end_precedes_start():
    assert parse_ip_range_or_cidr("192.168.1.254 - 192.168.1.1") is None


def test_parse_rejects_a_range_mixing_ip_versions():
    assert parse_ip_range_or_cidr("192.168.1.1 - ::1") is None


def test_parse_returns_none_for_a_plain_hostname():
    assert parse_ip_range_or_cidr("example.com") is None


def test_parse_returns_none_for_a_hyphenated_hostname_not_a_range():
    """A real hostname containing a literal hyphen (common in the wild) must never be
    misread as an IP range just because it has the right shape."""
    assert parse_ip_range_or_cidr("my-server.example.com") is None


def test_parse_does_not_rewrite_a_bare_single_ip_as_a_cidr():
    """A plain single IP (no "/") already works today as an exact-string match -- silently
    canonicalizing it to "x.x.x.x/32" would be a surprising, needless behavior change."""
    assert parse_ip_range_or_cidr("10.0.0.5") is None


# --- validate_scope_entry: New Project form's Target(s)/Out-of-scope fields ---


def test_validate_scope_entry_accepts_and_canonicalizes_a_cidr_block():
    assert validate_scope_entry("10.0.0.5/24") == "10.0.0.0/24"


def test_validate_scope_entry_accepts_and_canonicalizes_an_ip_range():
    assert validate_scope_entry("192.168.1.1 - 192.168.1.254") == "192.168.1.1-192.168.1.254"


def test_validate_scope_entry_still_rejects_a_genuinely_malformed_range():
    with pytest.raises(ValueError):
        validate_scope_entry("192.168.1.1 - not-an-ip")


# --- is_target_allowed / is_target_out_of_scope: real IP containment, both directions ---


def test_is_target_allowed_true_for_an_ip_inside_an_allowed_cidr_block():
    allowed_targets.add_allowed_target("10.0.0.0/24")
    assert is_target_allowed("10.0.0.5") is True
    assert is_target_allowed("https://10.0.0.200/login") is True


def test_is_target_allowed_false_for_an_ip_outside_an_allowed_cidr_block():
    allowed_targets.add_allowed_target("10.0.0.0/24")
    assert is_target_allowed("10.0.1.5") is False


def test_is_target_allowed_true_for_an_ip_inside_an_allowed_range():
    allowed_targets.add_allowed_target("192.168.1.1 - 192.168.1.254")
    assert is_target_allowed("192.168.1.130") is True


def test_is_target_allowed_false_for_an_ip_outside_an_allowed_range():
    allowed_targets.add_allowed_target("192.168.1.1 - 192.168.1.254")
    assert is_target_allowed("192.168.2.1") is False


def test_is_target_allowed_never_matches_a_hostname_against_a_cidr_block():
    """A hostname is never resolved just to test CIDR containment -- same "no DNS lookup" rule
    the wildcard-scope matching already follows."""
    allowed_targets.add_allowed_target("10.0.0.0/24")
    assert is_target_allowed("example.com") is False


def test_is_target_out_of_scope_true_for_an_ip_inside_an_excluded_cidr_block():
    assert is_target_out_of_scope("10.0.0.5", ["10.0.0.0/24"]) is True


def test_is_target_out_of_scope_true_for_an_ip_inside_an_excluded_range():
    assert is_target_out_of_scope("192.168.1.130", ["192.168.1.1-192.168.1.254"]) is True


def test_is_target_out_of_scope_false_for_an_ip_outside_the_excluded_pool():
    assert is_target_out_of_scope("10.0.1.5", ["10.0.0.0/24"]) is False


def test_plain_single_ip_scope_entries_still_match_exactly_as_before():
    """Regression guard: a plain IP entry (no CIDR/range involved at all) must keep matching
    exactly like it always has, unaffected by the new CIDR/range containment path."""
    allowed_targets.add_allowed_target("10.0.0.5")
    assert is_target_allowed("10.0.0.5") is True
    assert is_target_allowed("10.0.0.6") is False


def test_ipv6_cidr_block_is_supported_too():
    allowed_targets.add_allowed_target("2001:db8::/32")
    assert is_target_allowed("2001:db8::1") is True
    assert is_target_allowed("2001:db9::1") is False


def test_canonical_cidr_string_round_trips_through_ipaddress():
    """Sanity check the canonical form really is a real ipaddress network string, not just a
    string that happens to look like one."""
    assert ipaddress.ip_network(parse_ip_range_or_cidr("10.0.0.0/24")) == ipaddress.ip_network("10.0.0.0/24")
