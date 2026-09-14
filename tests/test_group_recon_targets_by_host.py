"""main.py's _group_recon_targets_by_host (Jinja filter "group_recon_targets_by_host") -- Recon
tab's own recon_result["targets"] is flat, one entry per open port (agent/core.py's record_target
is called once per port). Rendering one card per entry used to repeat the same host's own name/
known hostnames/resolved IPs/OS guess/Protection/Technologies once for every port it has; this
groups those entries into one entry per real physical host, using the same DNS-identity notion
agent/core.py's own _dedupe_hosts_by_dns_identity already applies (a hostname and its own resolved
IP are the SAME host, never two) -- see [[dojo_yeswehack_dns_identity]] for the incident that
introduced that notion in the first place.
"""
import main


def test_single_port_host_is_its_own_group_unchanged():
    targets = [{"host": "example.com", "port": 443, "service": "https", "version": "nginx"}]
    groups = main._group_recon_targets_by_host(targets, {}, {}, {}, {})
    assert len(groups) == 1
    assert groups[0]["primary_host"] == "example.com"
    assert groups[0]["ports"] == [{"host": "example.com", "port": 443, "service": "https", "version": "nginx", "index": 1}]


def test_multiple_ports_on_the_same_host_collapse_into_one_group():
    targets = [
        {"host": "example.com", "port": 22, "service": "ssh", "version": "OpenSSH"},
        {"host": "example.com", "port": 443, "service": "https", "version": "nginx"},
    ]
    groups = main._group_recon_targets_by_host(targets, {}, {}, {}, {})
    assert len(groups) == 1
    assert [p["port"] for p in groups[0]["ports"]] == [22, 443]
    # R# chat-reference numbering must survive grouping untouched -- agent/chat.py's
    # _session_snapshot numbers the ORIGINAL flat targets list, never the grouped one.
    assert [p["index"] for p in groups[0]["ports"]] == [1, 2]


def test_a_hostname_and_its_own_resolved_ip_merge_into_one_group():
    targets = [
        {"host": "example.com", "port": 443, "service": "https", "version": None},
        {"host": "203.0.113.42", "port": 22, "service": "ssh", "version": "OpenSSH"},
    ]
    dns_map = {"example.com": ["203.0.113.42"]}
    groups = main._group_recon_targets_by_host(targets, dns_map, {}, {}, {})
    assert len(groups) == 1
    assert [p["port"] for p in groups[0]["ports"]] == [443, 22]


def test_genuinely_distinct_hosts_stay_separate_groups():
    targets = [
        {"host": "a.example.com", "port": 80, "service": "http", "version": None},
        {"host": "b.example.com", "port": 80, "service": "http", "version": None},
    ]
    dns_map = {"a.example.com": ["10.0.0.1"], "b.example.com": ["10.0.0.2"]}
    groups = main._group_recon_targets_by_host(targets, dns_map, {}, {}, {})
    assert len(groups) == 2
    assert {g["primary_host"] for g in groups} == {"a.example.com", "b.example.com"}


def test_known_hostnames_lists_every_hostname_sharing_the_ip_not_just_the_first():
    targets = [{"host": "104.21.4.96", "port": 443, "service": "https", "version": None}]
    dns_map = {
        "library.example.com": ["104.21.4.96"],
        "p-ab-test.example.com": ["104.21.4.96"],
    }
    groups = main._group_recon_targets_by_host(targets, dns_map, {}, {}, {})
    assert groups[0]["is_ip"] is True
    assert set(groups[0]["known_hostnames"]) == {"library.example.com", "p-ab-test.example.com"}
    assert groups[0]["resolved_ips"] == []


def test_resolved_ips_shown_for_a_domain_primary_host():
    targets = [{"host": "example.com", "port": 443, "service": "https", "version": None}]
    dns_map = {"example.com": ["1.2.3.4"]}
    groups = main._group_recon_targets_by_host(targets, dns_map, {}, {}, {})
    assert groups[0]["is_ip"] is False
    assert groups[0]["resolved_ips"] == ["1.2.3.4"]
    assert groups[0]["known_hostnames"] == []


def test_os_guess_technologies_and_protections_looked_up_tolerantly_per_group():
    targets = [{"host": "example.com", "port": 443, "service": "https", "version": None}]
    os_guesses = {"https://example.com": "Linux"}
    technologies_by_host = {"https://example.com": ["nginx"]}
    protections_by_host = {"https://example.com": ["Cloudflare (WAF, nuclei global-waf-detect)"]}
    groups = main._group_recon_targets_by_host(targets, {}, os_guesses, technologies_by_host, protections_by_host)
    assert groups[0]["os_guess"] == "Linux"
    assert groups[0]["technologies"] == ["nginx"]
    assert groups[0]["protections"] == ["Cloudflare (WAF, nuclei global-waf-detect)"]


def test_a_target_with_no_host_is_skipped():
    targets = [{"host": "", "port": 80}, {"host": "example.com", "port": 443}]
    groups = main._group_recon_targets_by_host(targets, {}, {}, {}, {})
    assert len(groups) == 1
    assert groups[0]["primary_host"] == "example.com"
    assert groups[0]["ports"][0]["index"] == 2


def test_empty_input_returns_empty_list():
    assert main._group_recon_targets_by_host([], {}, {}, {}, {}) == []


def test_technology_certainty_is_looked_up_tolerantly_per_group():
    targets = [{"host": "example.com", "port": 443, "service": "https", "version": None}]
    technology_certainty_by_host = {"https://example.com": {"HTTPServer": 100, "WordPress": 90}}
    groups = main._group_recon_targets_by_host(targets, {}, {}, {}, {}, technology_certainty_by_host)
    assert groups[0]["technology_certainty"] == {"HTTPServer": 100, "WordPress": 90}


def test_technology_certainty_defaults_to_empty_dict_when_omitted():
    targets = [{"host": "example.com", "port": 443}]
    groups = main._group_recon_targets_by_host(targets, {}, {}, {}, {})
    assert groups[0]["technology_certainty"] == {}
