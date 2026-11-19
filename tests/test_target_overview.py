"""build_target_overview aggregates a session into the live Target Overview card
(agent/target_overview.py). It's a pure derivation of the session, reusing the derived finding
verification status (agent/verification_status.py), so these tests pin what it counts and that it
never fabricates state the session doesn't hold."""
from agent.target_overview import build_target_overview


def test_empty_session_has_no_data():
    overview = build_target_overview({})
    assert overview["has_data"] is False
    assert overview["surface"]["host_count"] == 0
    assert overview["findings"]["total"] == 0


def test_surface_counts_unique_scanned_hosts_only_not_dns_only_records():
    # A hostname that only RESOLVED (dns_map) but was never a scanned target must not inflate the
    # surface count or surface here -- it belongs on the Map tab's node list. (Also guards the Recon
    # tab: an unrelated resolved hostname must not leak into the overview card, see
    # tests/test_recon_asset_info_reverse_hostname.py.)
    session = {
        "recon_result": {
            "targets": [
                {"host": "a.example.com", "port": 443, "service": "https"},
                {"host": "a.example.com", "port": 80, "service": "http"},
            ],
            "dns_map": {"b.example.com": ["1.2.3.4"]},
        }
    }
    overview = build_target_overview(session)
    assert overview["has_data"] is True
    assert overview["surface"]["host_count"] == 1  # a.example.com, deduped across its two ports
    assert overview["surface"]["port_count"] == 2
    assert overview["surface"]["hosts"]["shown"] == ["a.example.com"]
    assert "b.example.com" not in overview["surface"]["hosts"]["shown"]


def test_stack_flattens_and_dedupes_technologies_and_protections():
    session = {
        "recon_result": {
            "technologies": {
                "a.example.com": ["HTTPServer[nginx]", "jQuery"],
                "b.example.com": ["HTTPServer[nginx]"],  # dup token across hosts collapses to one
            },
            "protections": {"a.example.com": ["cloudflare (WAF/CDN)"]},
        }
    }
    overview = build_target_overview(session)
    assert overview["stack"]["technologies"]["shown"].count("HTTPServer[nginx]") == 1
    assert "jQuery" in overview["stack"]["technologies"]["shown"]
    assert overview["stack"]["protections"]["shown"] == ["cloudflare (WAF/CDN)"]


def test_findings_break_down_by_derived_status_reusing_phase1():
    session = {
        "findings": [
            {"title": "A", "verification": "verified", "severity": "Critical", "exploited": True},
            {"title": "B", "verification": "verified", "ensemble_disagreement": True,
             "ensemble_secondary_verdict": "refuted", "severity": "High"},
            {"title": "C", "verification": "inferred", "severity": "Medium"},
        ],
    }
    overview = build_target_overview(session)
    assert overview["findings"]["total"] == 3
    assert overview["findings"]["verified"] == 1          # A (B is reclassified disputed)
    assert overview["findings"]["disputed"] == 1          # B
    assert overview["findings"]["by_status"]["inferred"] == 1  # C
    assert overview["findings"]["exploited"] == 1


def test_findings_fold_in_reverify_confirmed_fixed_as_fixed_status():
    session = {
        "findings": [{"title": "Old bug", "verification": "verified", "severity": "High"}],
        "reverification_history": [{"title": "Old bug", "verification_outcome": "confirmed_fixed"}],
    }
    overview = build_target_overview(session)
    assert overview["findings"]["by_status"].get("fixed") == 1
    assert overview["findings"]["verified"] == 0


def test_hypotheses_counted_by_status():
    session = {
        "hypotheses": [
            {"status": "unconfirmed"},
            {"status": "unconfirmed"},
            {"status": "confirmed"},
            {"status": "ruled_out"},
        ],
    }
    overview = build_target_overview(session)
    assert overview["hypotheses"] == {"total": 4, "open": 2, "confirmed": 1, "ruled_out": 1}


def test_knowledge_boundaries_separate_measured_from_suspected():
    session = {
        "findings": [
            {"title": "A", "verification": "verified", "severity": "Critical"},
            {"title": "B", "verification": "needs_verification", "severity": "Low"},
        ],
        "hypotheses": [{"status": "unconfirmed"}],
        "recon_result": {"targets": [{"host": "a.example.com", "port": 80}]},
    }
    knowledge = build_target_overview(session)["knowledge"]
    assert knowledge["verified_findings"] == 1
    assert knowledge["inferred_findings"] == 1   # the needs_verification one
    assert knowledge["open_hypotheses"] == 1
    assert knowledge["hosts_known"] == 1


def test_target_profile_facts_alone_count_as_data():
    session = {"target_profile": [{"label": "Architecture", "value": "x86-64", "source": "auto"}]}
    overview = build_target_overview(session)
    assert overview["has_data"] is True
    assert overview["profile_facts"][0]["label"] == "Architecture"


def test_long_lists_are_capped_with_a_more_count():
    session = {"recon_result": {"targets": [{"host": f"h{i}.example.com", "port": 80} for i in range(20)]}}
    overview = build_target_overview(session)
    assert len(overview["surface"]["hosts"]["shown"]) == 12
    assert overview["surface"]["hosts"]["more"] == 8
