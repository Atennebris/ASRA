"""main.py's _build_attack_surface_graph -- the Map tab's Attack Surface sub-view. Nodes reuse
_group_recon_targets_by_host's own DNS-identity merge (see tests/test_group_recon_targets_by_host.py
for that function's own coverage), colored by the worst severity among findings/hypotheses whose
own optional "host" field (record_finding/record_hypothesis) matches this host's identity set.
Edges come from dns_map (domain -> its own resolved IPs) and session["asset_graph"]["credentials"]
(credential reuse across hosts, agent/core.py's _update_asset_graph) -- the same data the Chain tab
already renders as plain text, given a real graph position here instead.
"""
import main


def _session(**kwargs) -> dict:
    base = {"recon_result": {}, "findings": [], "hypotheses": [], "asset_graph": {}}
    base.update(kwargs)
    return base


def test_no_targets_returns_empty_graph():
    graph = main._build_attack_surface_graph(_session())
    assert graph == {"nodes": [], "edges": [], "hidden_count": 0}


def test_single_target_becomes_one_unlocated_node():
    session = _session(recon_result={"targets": [{"host": "example.com", "port": 443, "service": "https"}]})
    graph = main._build_attack_surface_graph(session)
    assert len(graph["nodes"]) == 1
    node = graph["nodes"][0]
    assert node["id"] == "example.com"
    assert node["worst_severity"] is None
    assert node["finding_count_by_severity"] == {}
    assert node["ports"] == [{"port": 443, "service": "https"}]


def test_a_hostname_and_its_own_resolved_ip_stay_one_node():
    session = _session(recon_result={
        "targets": [
            {"host": "example.com", "port": 443, "service": "https"},
            {"host": "203.0.113.42", "port": 22, "service": "ssh"},
        ],
        "dns_map": {"example.com": ["203.0.113.42"]},
    })
    graph = main._build_attack_surface_graph(session)
    assert len(graph["nodes"]) == 1
    assert graph["nodes"][0]["id"] == "example.com"


def test_finding_with_matching_host_colors_the_right_node():
    session = _session(
        recon_result={"targets": [
            {"host": "a.example.com", "port": 80},
            {"host": "b.example.com", "port": 80},
        ]},
        findings=[{"host": "a.example.com", "severity": "Critical"}],
    )
    graph = main._build_attack_surface_graph(session)
    by_id = {n["id"]: n for n in graph["nodes"]}
    assert by_id["a.example.com"]["worst_severity"] == "Critical"
    assert by_id["a.example.com"]["finding_count_by_severity"] == {"Critical": 1}
    assert by_id["b.example.com"]["worst_severity"] is None


def test_worst_severity_picks_the_highest_when_a_host_has_several_findings():
    session = _session(
        recon_result={"targets": [{"host": "example.com", "port": 80}]},
        findings=[
            {"host": "example.com", "severity": "Low"},
            {"host": "example.com", "severity": "High"},
            {"host": "example.com", "severity": "Medium"},
        ],
    )
    graph = main._build_attack_surface_graph(session)
    assert graph["nodes"][0]["worst_severity"] == "High"
    assert graph["nodes"][0]["finding_count_by_severity"] == {"Low": 1, "High": 1, "Medium": 1}


def test_finding_with_no_host_field_stays_unlocated_not_erroring():
    session = _session(
        recon_result={"targets": [{"host": "example.com", "port": 80}]},
        findings=[{"severity": "Critical"}],  # no "host" -- a finding recorded before this field existed
    )
    graph = main._build_attack_surface_graph(session)
    assert graph["nodes"][0]["worst_severity"] is None


def test_hypothesis_count_matches_by_host_the_same_way_findings_do():
    session = _session(
        recon_result={"targets": [{"host": "example.com", "port": 80}]},
        hypotheses=[
            {"host": "example.com", "status": "unconfirmed"},
            {"host": "other.example.com", "status": "unconfirmed"},
        ],
    )
    graph = main._build_attack_surface_graph(session)
    assert graph["nodes"][0]["hypothesis_count"] == 1


def test_an_open_hypothesis_with_no_confirmed_finding_flags_the_node_without_a_fake_severity():
    # record_hypothesis has no "severity" field at all -- a real, confirmed bug this replaces
    # pretended it did (hypothesis.get("severity")), which never actually worked in a real session
    # (that key simply doesn't exist there). An open hypothesis flags has_open_hypothesis instead
    # of inventing a severity color for something that was never scored one.
    session = _session(
        recon_result={"targets": [{"host": "example.com", "port": 80}]},
        hypotheses=[{"host": "example.com", "status": "unconfirmed"}],
    )
    node = main._build_attack_surface_graph(session)["nodes"][0]
    assert node["worst_severity"] is None
    assert node["has_open_hypothesis"] is True
    assert node["hypothesis_count"] == 1


def test_a_confirmed_finding_and_an_open_hypothesis_both_show_on_the_same_node():
    session = _session(
        recon_result={"targets": [{"host": "example.com", "port": 80}]},
        findings=[{"host": "example.com", "severity": "Critical"}],
        hypotheses=[{"host": "example.com", "status": "unconfirmed"}],
    )
    node = main._build_attack_surface_graph(session)["nodes"][0]
    assert node["worst_severity"] == "Critical"
    assert node["has_open_hypothesis"] is True


def test_a_hypothesis_with_no_host_field_matches_by_text_substring_instead():
    # Real, confirmed: record_hypothesis's own "host" field is almost never actually populated in
    # practice (0 of 4 in a real operator session) -- the model's own free-text "text" field is
    # what actually names the host in real usage, so that's the fallback that has to work.
    session = _session(
        recon_result={"targets": [{"host": "example.com", "port": 80}]},
        hypotheses=[{"text": "example.com's /login endpoint may leak a session token", "status": "unconfirmed"}],
    )
    node = main._build_attack_surface_graph(session)["nodes"][0]
    assert node["has_open_hypothesis"] is True


def test_a_confirmed_or_ruled_out_hypothesis_is_not_open():
    session = _session(
        recon_result={"targets": [{"host": "example.com", "port": 80}]},
        hypotheses=[
            {"host": "example.com", "status": "confirmed"},
            {"host": "example.com", "status": "ruled_out"},
        ],
    )
    node = main._build_attack_surface_graph(session)["nodes"][0]
    assert node["has_open_hypothesis"] is False
    assert node["hypothesis_count"] == 0


def test_domain_only_node_added_for_a_dns_map_entry_never_port_scanned():
    session = _session(recon_result={"dns_map": {"sub.example.com": ["1.2.3.4"]}})
    graph = main._build_attack_surface_graph(session)
    assert len(graph["nodes"]) == 1
    assert graph["nodes"][0]["id"] == "sub.example.com"
    assert graph["nodes"][0]["resolved_ips"] == ["1.2.3.4"]


def test_dns_edge_connects_domain_to_its_resolved_ip_node():
    session = _session(recon_result={
        "targets": [
            {"host": "example.com", "port": 443},
            {"host": "5.6.7.8", "port": 443},
        ],
        "dns_map": {"example.com": ["5.6.7.8"]},
    })
    graph = main._build_attack_surface_graph(session)
    # example.com/5.6.7.8 merge into ONE node (DNS-identity) -- no self-edge should be emitted.
    assert graph["edges"] == []


def test_dns_edge_connects_two_genuinely_distinct_nodes():
    # A domain a hostname's own dns_map entry does NOT already identity-merge into an existing
    # target group is the only case that can produce a real cross-node DNS edge -- b.example.com is
    # never port-scanned (not in targets), but shares a.example.com's own resolved IP, so it becomes
    # its own domain-only node genuinely connected to a.example.com's node, not the same node.
    session = _session(recon_result={
        "targets": [{"host": "a.example.com", "port": 80}],
        "dns_map": {"a.example.com": ["9.9.9.9"], "b.example.com": ["9.9.9.9"]},
    })
    graph = main._build_attack_surface_graph(session)
    assert len(graph["edges"]) == 1
    edge = graph["edges"][0]
    assert edge["source"] == "b.example.com"
    assert edge["target"] == "a.example.com"
    assert edge["kind"] == "dns"
    assert edge["direction"] == "forward"
    assert edge["manual"] is False


def test_credential_reuse_edge_connects_two_hosts_sharing_one_pair():
    session = _session(
        recon_result={"targets": [{"host": "a.example.com", "port": 80}, {"host": "b.example.com", "port": 80}]},
        asset_graph={"credentials": [
            {"username": "admin", "password": "pw", "found_on_host": "a.example.com"},
            {"username": "admin", "password": "pw", "found_on_host": "b.example.com"},
        ]},
    )
    graph = main._build_attack_surface_graph(session)
    reuse_edges = [e for e in graph["edges"] if e["kind"] == "credential_reuse"]
    assert len(reuse_edges) == 1
    assert {reuse_edges[0]["source"], reuse_edges[0]["target"]} == {"a.example.com", "b.example.com"}


def test_credential_found_on_only_one_host_produces_no_edge():
    session = _session(
        recon_result={"targets": [{"host": "a.example.com", "port": 80}]},
        asset_graph={"credentials": [{"username": "admin", "password": "pw", "found_on_host": "a.example.com"}]},
    )
    graph = main._build_attack_surface_graph(session)
    assert graph["edges"] == []


def test_worst_severity_helper_returns_none_for_empty_input():
    assert main._worst_severity([]) is None


def test_worst_severity_helper_ranks_critical_above_everything():
    assert main._worst_severity(["Low", "Medium", "Critical", "High"]) == "Critical"


def test_a_manual_node_appears_in_the_graph_flagged_manual():
    session = _session(map_manual={"nodes": [{"id": "manual-abc", "label": "Third-party VPN", "kind": "actor", "notes": "external"}], "edges": [], "positions": {}})
    graph = main._build_attack_surface_graph(session)
    assert len(graph["nodes"]) == 1
    node = graph["nodes"][0]
    assert node["id"] == "manual-abc"
    assert node["label"] == "Third-party VPN"
    assert node["kind"] == "actor"
    assert node["notes"] == "external"
    assert node["manual"] is True


def test_a_manual_edge_between_a_manual_node_and_a_real_host_carries_its_own_metadata():
    session = _session(
        recon_result={"targets": [{"host": "example.com", "port": 443}]},
        map_manual={
            "nodes": [{"id": "manual-abc", "label": "Attacker", "kind": "actor", "notes": ""}],
            "edges": [{"id": "manual-edge-1", "source": "manual-abc", "target": "example.com",
                       "direction": "forward", "data_type": "C2 beacon", "volume": "2KB",
                       "format": "HTTPS POST", "interval": "every 60s", "label": "", "notes": ""}],
            "positions": {},
        },
    )
    graph = main._build_attack_surface_graph(session)
    manual_edges = [e for e in graph["edges"] if e["manual"]]
    assert len(manual_edges) == 1
    edge = manual_edges[0]
    assert edge["source"] == "manual-abc"
    assert edge["target"] == "example.com"
    assert edge["kind"] == "manual"
    assert edge["direction"] == "forward"
    assert edge["data_type"] == "C2 beacon"
    assert edge["volume"] == "2KB"
    assert edge["format"] == "HTTPS POST"
    assert edge["interval"] == "every 60s"
    # No operator-set label -- falls back to data_type so the edge isn't shown blank on canvas.
    assert edge["label"] == "C2 beacon"


def test_a_saved_position_is_attached_to_the_matching_node():
    session = _session(
        recon_result={"targets": [{"host": "example.com", "port": 443}]},
        map_manual={"nodes": [], "edges": [], "positions": {"example.com": {"x": 120.5, "y": 40.0}}},
    )
    node = main._build_attack_surface_graph(session)["nodes"][0]
    assert node["position"] == {"x": 120.5, "y": 40.0}


def test_a_node_with_no_saved_position_gets_none():
    session = _session(recon_result={"targets": [{"host": "example.com", "port": 443}]})
    node = main._build_attack_surface_graph(session)["nodes"][0]
    assert node["position"] is None


def test_two_different_hostnames_sharing_one_ip_merge_into_one_node_not_two():
    # Real, confirmed bug: _group_recon_targets_by_host's own known_hostnames field stays empty
    # whenever the primary host is a hostname (it's populated for a DIFFERENT case -- the same
    # physical host recorded once by name and once by its own IP) -- so a second, genuinely
    # different hostname sharing the group's IP (two subdomains behind one load balancer) never
    # showed up in `identities` here, and got a spurious second "domain-only" node instead of
    # correctly matching into the already-merged group.
    session = _session(
        recon_result={
            "targets": [
                {"host": "a.example.com", "port": 443},
                {"host": "b.example.com", "port": 443},
            ],
            "dns_map": {"a.example.com": ["9.9.9.9"], "b.example.com": ["9.9.9.9"]},
        },
        findings=[{"host": "b.example.com", "severity": "Critical"}],
    )
    graph = main._build_attack_surface_graph(session)
    assert len(graph["nodes"]) == 1
    node = graph["nodes"][0]
    assert node["worst_severity"] == "Critical"
    assert node["finding_count_by_severity"] == {"Critical": 1}
    # The second real hostname must stay visible somewhere on the merged node -- previously it
    # merged correctly for SEVERITY purposes but was invisible everywhere in the UI (known_hostnames
    # relied on the group's own field, which stays empty in exactly this case), reading as "a real
    # target the operator gave the agent silently vanished from the map".
    assert "b.example.com" in node["known_hostnames"]


def test_a_finding_with_no_host_field_matches_by_title_substring_instead():
    # Real, confirmed bug: findings never had hypotheses' own text-fallback match -- record_finding's
    # own "host" field is rarely set in practice (confirmed live: 16 of 21 in a real session), so
    # most confirmed findings never colored any node at all.
    session = _session(
        recon_result={"targets": [{"host": "play.example.com", "port": 3389}]},
        findings=[{"title": "Internet-exposed RDP on play.example.com:3389", "severity": "High"}],
    )
    node = main._build_attack_surface_graph(session)["nodes"][0]
    assert node["worst_severity"] == "High"


def test_title_substring_match_prefers_the_longer_more_specific_identity():
    # Real, confirmed bug: picking the first identities_by_node match (dict insertion order) let a
    # short, generic identity ("example.com") steal a match meant for its own subdomain
    # ("play.example.com" contains "example.com" as a literal substring).
    session = _session(
        recon_result={
            "targets": [
                {"host": "example.com", "port": 443},
                {"host": "play.example.com", "port": 3389},
            ],
        },
        findings=[{"title": "Internet-exposed RDP on play.example.com:3389", "severity": "High"}],
    )
    graph = main._build_attack_surface_graph(session)
    by_id = {n["id"]: n for n in graph["nodes"]}
    assert by_id["play.example.com"]["worst_severity"] == "High"
    assert by_id["example.com"]["worst_severity"] is None


def test_group_recon_targets_by_host_receives_the_real_technologies_protections_keys():
    # Real, confirmed bug this fixes: _build_attack_surface_graph used to pass
    # technologies_by_host/protections_by_host (keys recon_result never actually has) instead of
    # the real "technologies"/"protections" keys, so every node's own tech/protection data was
    # silently always empty.
    session = _session(recon_result={
        "targets": [{"host": "example.com", "port": 443}],
        "technologies": {"example.com": ["HTTPServer[nginx]"]},
    })
    node = main._build_attack_surface_graph(session)["nodes"][0]
    assert "HTTPServer[nginx]" in node["technologies"]


def test_shared_surface_noise_tokens_are_excluded():
    session = _session(recon_result={
        "targets": [{"host": "a.example.com", "port": 443}, {"host": "b.example.com", "port": 443}],
        "technologies": {
            "a.example.com": ["Title[Same Page Title]"],
            "b.example.com": ["Title[Same Page Title]"],
        },
    })
    graph = main._build_attack_surface_graph(session)
    assert [e for e in graph["edges"] if e["kind"] == "shared_surface"] == []


def test_shared_surface_edge_connects_hosts_sharing_a_real_technology_token():
    session = _session(recon_result={
        "targets": [{"host": "a.example.com", "port": 443}, {"host": "b.example.com", "port": 443}],
        "technologies": {
            "a.example.com": ["HTTPServer[nginx]"],
            "b.example.com": ["HTTPServer[nginx]"],
        },
    })
    graph = main._build_attack_surface_graph(session)
    edges = [e for e in graph["edges"] if e["kind"] == "shared_surface"]
    assert len(edges) == 1
    assert {edges[0]["source"], edges[0]["target"]} == {"a.example.com", "b.example.com"}
    assert edges[0]["label"] == "HTTPServer[nginx]"


def test_shared_surface_edge_from_matching_waf_label():
    session = _session(recon_result={
        "targets": [{"host": "a.example.com", "port": 443}, {"host": "b.example.com", "port": 443}],
        "protections": {
            "a.example.com": ["cloudflare (WAF/CDN, whatweb, via HTTPServer, 100% certainty)"],
            "b.example.com": ["cloudflare (WAF/CDN, whatweb, via HTTPServer, 90% certainty)"],
        },
    })
    graph = main._build_attack_surface_graph(session)
    edges = [e for e in graph["edges"] if e["kind"] == "shared_surface"]
    assert len(edges) == 1
    assert edges[0]["label"] == "cloudflare"


def test_shared_surface_edge_from_a_shared_tls_certificate_san():
    session = _session(recon_result={
        "targets": [{"host": "a.example.com", "port": 443}, {"host": "b.example.com", "port": 443}],
        "tls_sans": {"a.example.com": ["*.example.com"], "b.example.com": ["*.example.com"]},
    })
    graph = main._build_attack_surface_graph(session)
    edges = [e for e in graph["edges"] if e["kind"] == "shared_surface"]
    assert len(edges) == 1
    assert edges[0]["label"] == "cert: *.example.com"


def test_shared_surface_skips_a_signal_shared_by_too_many_hosts():
    hosts = [f"h{i}.example.com" for i in range(main._MAP_SHARED_SURFACE_MAX_FANOUT + 1)]
    session = _session(
        recon_result={
            "targets": [{"host": h, "port": 443} for h in hosts],
            "technologies": {h: ["HTTPServer[nginx]"] for h in hosts},
        },
    )
    graph = main._build_attack_surface_graph(session)
    assert [e for e in graph["edges"] if e["kind"] == "shared_surface"] == []


def test_domain_family_edge_connects_a_subdomain_to_its_own_apex_when_both_are_nodes():
    session = _session(recon_result={
        "targets": [{"host": "example.com", "port": 443}, {"host": "portal.example.com", "port": 443}],
    })
    graph = main._build_attack_surface_graph(session)
    edges = [e for e in graph["edges"] if e["kind"] == "domain_family"]
    assert len(edges) == 1
    assert edges[0]["source"] == "example.com"
    assert edges[0]["target"] == "portal.example.com"


def test_domain_family_never_invents_a_phantom_apex_node():
    session = _session(recon_result={"targets": [{"host": "portal.example.com", "port": 443}]})
    graph = main._build_attack_surface_graph(session)
    assert [e for e in graph["edges"] if e["kind"] == "domain_family"] == []


def test_attack_path_edge_from_a_chain_attempt_naming_two_hosts():
    session = _session(
        recon_result={"targets": [{"host": "a.example.com", "port": 80}, {"host": "b.example.com", "port": 80}]},
        findings=[
            {"title": "SSRF on a.example.com", "host": "a.example.com", "severity": "High"},
            {"title": "Internal admin panel on b.example.com", "host": "b.example.com", "severity": "Critical"},
        ],
        chain_attempts=[{
            "outcome": "chain_confirmed",
            "finding_titles": ["SSRF on a.example.com", "Internal admin panel on b.example.com"],
            "reasoning": "SSRF on a.example.com was used to reach the internal admin panel on b.example.com.",
        }],
    )
    graph = main._build_attack_surface_graph(session)
    edges = [e for e in graph["edges"] if e["kind"] == "attack_path"]
    assert len(edges) == 1
    assert edges[0]["source"] == "a.example.com"
    assert edges[0]["target"] == "b.example.com"
    assert edges[0]["label"] == "chain_confirmed"
    assert "SSRF" in edges[0]["notes"]


def test_chain_attempt_naming_only_one_host_produces_no_attack_path_edge():
    session = _session(
        recon_result={"targets": [{"host": "a.example.com", "port": 80}]},
        findings=[{"title": "SSRF on a.example.com", "host": "a.example.com", "severity": "High"}],
        chain_attempts=[{"outcome": "no_chain_found", "finding_titles": ["SSRF on a.example.com"], "reasoning": "no"}],
    )
    graph = main._build_attack_surface_graph(session)
    assert [e for e in graph["edges"] if e["kind"] == "attack_path"] == []


def test_agent_relationship_produces_a_high_fidelity_attack_path_edge():
    session = _session(
        recon_result={"targets": [{"host": "a.example.com", "port": 80}, {"host": "b.example.com", "port": 80}]},
        agent_relationships=[{
            "source_host": "a.example.com", "target_host": "b.example.com",
            "mechanism": "leaked credentials", "evidence": "authenticated_request with leaked creds succeeded",
            "recorded_at": "2026-01-01T00:00:00+00:00",
        }],
    )
    graph = main._build_attack_surface_graph(session)
    edges = [e for e in graph["edges"] if e["kind"] == "attack_path"]
    assert len(edges) == 1
    assert edges[0]["label"] == "leaked credentials"
    assert edges[0]["notes"] == "authenticated_request with leaked creds succeeded"
    assert edges[0]["at"] == "2026-01-01T00:00:00+00:00"


def test_agent_relationship_edge_wins_dedup_over_a_chain_derived_one_for_the_same_pair():
    session = _session(
        recon_result={"targets": [{"host": "a.example.com", "port": 80}, {"host": "b.example.com", "port": 80}]},
        findings=[
            {"title": "SSRF on a.example.com", "host": "a.example.com", "severity": "High"},
            {"title": "Admin panel on b.example.com", "host": "b.example.com", "severity": "Critical"},
        ],
        chain_attempts=[{
            "outcome": "chain_confirmed",
            "finding_titles": ["SSRF on a.example.com", "Admin panel on b.example.com"],
            "reasoning": "chain reasoning",
        }],
        agent_relationships=[{
            "source_host": "a.example.com", "target_host": "b.example.com",
            "mechanism": "SSRF", "evidence": "real evidence",
        }],
    )
    graph = main._build_attack_surface_graph(session)
    edges = [e for e in graph["edges"] if e["kind"] == "attack_path"]
    assert len(edges) == 1
    assert edges[0]["label"] == "SSRF"  # the explicit agent_relationships label, not "chain_confirmed"


def test_has_confirmed_access_true_only_when_a_finding_is_actually_exploited():
    session = _session(
        recon_result={"targets": [{"host": "example.com", "port": 80}]},
        findings=[{"host": "example.com", "severity": "Critical", "exploited": True}],
    )
    node = main._build_attack_surface_graph(session)["nodes"][0]
    assert node["has_confirmed_access"] is True


def test_has_confirmed_access_false_when_finding_exists_but_not_exploited():
    session = _session(
        recon_result={"targets": [{"host": "example.com", "port": 80}]},
        findings=[{"host": "example.com", "severity": "Critical", "exploited": False}],
    )
    node = main._build_attack_surface_graph(session)["nodes"][0]
    assert node["has_confirmed_access"] is False


def test_surface_score_grows_with_severity_confirmed_access_and_risky_ports():
    plain = main._build_attack_surface_graph(_session(
        recon_result={"targets": [{"host": "a.example.com", "port": 80}]},
    ))["nodes"][0]
    risky = main._build_attack_surface_graph(_session(
        recon_result={"targets": [{"host": "b.example.com", "port": 3389}]},
        findings=[{"host": "b.example.com", "severity": "Critical", "exploited": True}],
    ))["nodes"][0]
    assert risky["surface_score"] > plain["surface_score"]


def test_first_seen_at_uses_the_earliest_target_discovery_timestamp():
    session = _session(recon_result={"targets": [
        {"host": "example.com", "port": 80, "discovered_at": "2026-02-01T00:00:00+00:00"},
        {"host": "example.com", "port": 443, "discovered_at": "2026-01-01T00:00:00+00:00"},
    ]})
    node = main._build_attack_surface_graph(session)["nodes"][0]
    assert node["first_seen_at"] == "2026-01-01T00:00:00+00:00"


def test_first_seen_at_is_none_when_no_source_has_a_timestamp():
    session = _session(recon_result={"targets": [{"host": "example.com", "port": 80}]})
    node = main._build_attack_surface_graph(session)["nodes"][0]
    assert node["first_seen_at"] is None
