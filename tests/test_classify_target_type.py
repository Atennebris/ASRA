"""classify_target_type (agent/tools/builders/validators.py) -- purely informational label used by
templates/macros/ui.html's target_type_badges(), never a validation/routing decision. Covers every
real bucket plus the two documented edge cases (bracketed IPv6+port, host+port) that deliberately
fall through to a slightly-wrong-but-harmless label rather than needing a heavier parser.
"""
from agent.tools.builders.validators import classify_target_type


def test_classifies_cidr_as_subnet():
    assert classify_target_type("10.0.0.0/24") == "subnet"


def test_classifies_ip_range_as_subnet():
    assert classify_target_type("10.0.0.5-10.0.0.9") == "subnet"


def test_classifies_bare_ipv4_as_ip():
    assert classify_target_type("1.2.3.4") == "ip"


def test_classifies_bare_ipv6_as_ip():
    assert classify_target_type("2001:db8::1") == "ip"


def test_classifies_wildcard_domain_as_wildcard():
    assert classify_target_type("*.example.com") == "wildcard"


def test_classifies_url_with_scheme_as_url():
    assert classify_target_type("https://api.example.com/login?x=1") == "url"


def test_classifies_bare_host_with_path_as_url():
    assert classify_target_type("example.com/path") == "url"


def test_classifies_fqdn_as_domain():
    assert classify_target_type("api.example.com") == "domain"


def test_classifies_cyrillic_domain_as_domain():
    assert classify_target_type("банк.рф") == "domain"


def test_classifies_single_label_as_host():
    assert classify_target_type("localhost") == "host"


def test_empty_string_classifies_as_host():
    assert classify_target_type("") == "host"


def test_bracketed_ipv6_with_port_is_a_known_limitation_not_ip():
    """Documented limitation: a bracketed IPv6 literal with an explicit port isn't stripped down
    to a bare address -- ipaddress.ip_address rejects it and it falls through past "ip"."""
    assert classify_target_type("[::1]:8443") == "host"


def test_domain_with_port_is_a_known_limitation_still_domain():
    """Documented limitation: the port suffix doesn't change the bucket -- still labeled "domain",
    which is close enough for a display-only chip."""
    assert classify_target_type("example.com:8443") == "domain"
