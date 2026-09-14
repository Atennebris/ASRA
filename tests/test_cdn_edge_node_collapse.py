"""collapse_cdn_edge_node_hosts (agent/tools/allowed_targets.py) -- collapses a flood of
CDN/edge-node-style hostnames that differ from each other only in numeric segments down to a
couple of representative samples plus a count, before a subdomain discovery tool's raw result
ever reaches the model.

Real, confirmed incident this covers (a real HackerOne session): `subfinder -d example-cdn.net`
returned thousands of hosts shaped like "ipv4-c017-ord003-ix.1.oca.example-cdn.net" -- one subagent
correctly improvised "filter out CDN node patterns" as an ad-hoc plan step, another one didn't and
burned several whatweb calls against hosts that don't even resolve (NXDOMAIN). This test file
covers the shared helper directly; tests/test_subfinder_builder.py and this file's own
crt_sh_lookup test cover both of its real call sites.
"""
from agent.tools.allowed_targets import collapse_cdn_edge_node_hosts


def test_small_lists_pass_through_untouched():
    hosts = ["a.example.com", "b.example.com", "c.example.com"]
    assert collapse_cdn_edge_node_hosts(hosts) == hosts


def test_a_handful_of_genuinely_distinct_numbered_hosts_is_not_collapsed():
    """www1/www2/ns1 differ only in digits too, but there are only 3 of them -- collapsing a
    group this small would swallow real, distinct attack surface for no real benefit."""
    hosts = ["www1.example.com", "www2.example.com", "ns1.example.com"]
    assert collapse_cdn_edge_node_hosts(hosts) == hosts


def test_a_large_cdn_style_fan_out_collapses_to_samples_plus_a_count():
    hosts = [f"ipv4-c{i:03d}-ord003-ix.1.oca.example-cdn.net" for i in range(50)]
    result = collapse_cdn_edge_node_hosts(hosts)
    assert len(result) == 3  # 2 samples + 1 marker
    assert result[0] == "ipv4-c000-ord003-ix.1.oca.example-cdn.net"
    assert result[1] == "ipv4-c001-ord003-ix.1.oca.example-cdn.net"
    assert "48 more" in result[2]
    assert "collapsed" in result[2]


def test_multiple_distinct_patterns_are_grouped_and_collapsed_independently():
    fan_out_a = [f"ipv4-c{i:03d}-ord003-ix.1.oca.example-cdn.net" for i in range(10)]
    fan_out_b = [f"edge{i:02d}.cdn.example.com" for i in range(10)]
    result = collapse_cdn_edge_node_hosts(fan_out_a + fan_out_b)
    assert len(result) == 6  # (2 samples + 1 marker) per pattern, two patterns
    markers = [entry for entry in result if "more" in entry]
    assert len(markers) == 2


def test_no_provider_name_is_hardcoded_generic_pattern_works_for_any_naming_scheme():
    """Same shape, unrelated to any real CDN/provider name -- the function reacts purely to
    digit-run structure, not a hardcoded vendor string."""
    hosts = [f"worker-{i}.internal.example.org" for i in range(30)]
    result = collapse_cdn_edge_node_hosts(hosts)
    assert len(result) == 3
    assert "28 more" in result[2]


def test_crt_sh_lookup_collapses_a_large_result_before_returning_it(monkeypatch, tmp_path):
    import agent.tools.cache as cache
    import agent.tools.native as native

    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(
        native, "_crt_sh_subdomains",
        lambda domain, client: {f"ipv4-c{i:03d}-ord003-ix.1.oca.example-cdn.net" for i in range(20)},
    )

    result = native.crt_sh_lookup({"domain": "example-cdn.net"})

    assert result["status"] == "ok"
    assert len(result["subdomains"]) == 3
    assert "collapsed" in result["subdomains"][-1]
