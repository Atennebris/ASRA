"""_dedupe_hosts_by_dns_identity (agent/core.py): a hostname and its own resolved IP must never
count as two distinct hosts when deciding how many "secondary hosts" exist for auto-delegation.
Real, confirmed incident this fixes: recon_result["targets"] recorded example.com (from an
httpx probe) and its own resolved 203.0.113.42 (from nmap's IP-based output) as two separate
entries -- _auto_delegate_analyze_overflow's plain string dedup treated them as 2 distinct
"secondary hosts" worth splitting off to a subagent, whose first action was to re-run the identical
nmap scan Recon had already just run against the same physical target seconds earlier.
"""
from agent.core import _dedupe_hosts_by_dns_identity


def test_collapses_a_hostname_and_its_own_resolved_ip():
    hosts = ["example.com", "203.0.113.42"]
    dns_map = {"example.com": ["203.0.113.42"]}
    assert _dedupe_hosts_by_dns_identity(hosts, dns_map) == ["example.com"]


def test_collapses_regardless_of_which_order_they_appear_in():
    hosts = ["203.0.113.42", "example.com"]
    dns_map = {"example.com": ["203.0.113.42"]}
    assert _dedupe_hosts_by_dns_identity(hosts, dns_map) == ["203.0.113.42"]


def test_genuinely_distinct_hosts_are_all_kept():
    hosts = ["a.example.com", "b.example.com", "c.example.com"]
    dns_map = {"a.example.com": ["10.0.0.1"], "b.example.com": ["10.0.0.2"], "c.example.com": ["10.0.0.3"]}
    assert _dedupe_hosts_by_dns_identity(hosts, dns_map) == hosts


def test_no_dns_map_data_at_all_is_a_no_op():
    hosts = ["a.example.com", "b.example.com"]
    assert _dedupe_hosts_by_dns_identity(hosts, {}) == hosts


def test_two_hostnames_sharing_the_same_resolved_ip_are_collapsed_too():
    # A real, if less common, shape: two hostnames on the same shared/load-balanced IP -- treated
    # as one identity group the same way, keeping only the first one seen.
    hosts = ["www.example.com", "app.example.com"]
    dns_map = {"www.example.com": ["10.0.0.1"], "app.example.com": ["10.0.0.1"]}
    assert _dedupe_hosts_by_dns_identity(hosts, dns_map) == ["www.example.com"]
