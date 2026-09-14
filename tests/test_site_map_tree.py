"""main.py's _build_site_map_tree -- the Map tab's Site Tree sub-view. Groups the SAME flat
captured-traffic entries the Toolkit's own proxy-history table (toolkit_traffic_list.html) already
renders as a list into a real host -> URL-path hierarchy (OWASP ZAP's own "Sites tree" shape) --
a different, aggregated view of identical data, not a second capture mechanism.

Returns {"in_scope": [...], "other": [...]} rather than one flat list -- with no scope_entries
given (or an empty list), everything lands in "in_scope" (see the function's own docstring for why:
"no scope known yet" must never mislabel real targets as noise), which is what every test below
that doesn't pass scope_entries relies on.
"""
import main


def test_empty_entries_returns_empty_groups():
    assert main._build_site_map_tree([]) == {"in_scope": [], "other": []}


def test_single_entry_becomes_one_host_with_a_nested_path():
    entries = [{"id": "1", "method": "GET", "url": "https://example.com/api/users", "response_status": 200}]
    tree = main._build_site_map_tree(entries)["in_scope"]
    assert len(tree) == 1
    host = tree[0]
    assert host["name"] == "example.com"
    assert len(host["children"]) == 1
    api_node = host["children"][0]
    assert api_node["name"] == "api"
    assert len(api_node["children"]) == 1
    users_node = api_node["children"][0]
    assert users_node["name"] == "users"
    assert len(users_node["leaves"]) == 1
    assert users_node["leaves"][0]["id"] == "1"
    assert users_node["leaves"][0]["status"] == 200


def test_two_entries_sharing_a_path_prefix_share_the_same_tree_nodes():
    entries = [
        {"id": "1", "method": "GET", "url": "https://example.com/api/users", "response_status": 200},
        {"id": "2", "method": "GET", "url": "https://example.com/api/orders", "response_status": 200},
    ]
    tree = main._build_site_map_tree(entries)["in_scope"]
    api_node = tree[0]["children"][0]
    assert {c["name"] for c in api_node["children"]} == {"users", "orders"}


def test_root_path_entry_becomes_a_leaf_directly_on_the_host_node():
    entries = [{"id": "1", "method": "GET", "url": "https://example.com/", "response_status": 200}]
    tree = main._build_site_map_tree(entries)["in_scope"]
    assert tree[0]["children"] == []
    assert len(tree[0]["leaves"]) == 1


def test_different_hosts_become_separate_top_level_tree_entries():
    entries = [
        {"id": "1", "method": "GET", "url": "https://a.example.com/x", "response_status": 200},
        {"id": "2", "method": "GET", "url": "https://b.example.com/y", "response_status": 200},
    ]
    tree = main._build_site_map_tree(entries)["in_scope"]
    assert {h["name"] for h in tree} == {"a.example.com", "b.example.com"}


def test_passive_detector_flags_survive_onto_the_right_leaf():
    entries = [{"id": "1", "method": "GET", "url": "https://example.com/admin", "response_status": 200, "flags": ["open_redirect"]}]
    tree = main._build_site_map_tree(entries)["in_scope"]
    leaf = tree[0]["children"][0]["leaves"][0]
    assert leaf["flags"] == ["open_redirect"]


def test_entry_with_missing_url_groups_under_unknown_host():
    entries = [{"id": "1", "method": "GET", "url": None, "response_status": None}]
    tree = main._build_site_map_tree(entries)["in_scope"]
    assert tree[0]["name"] == "(unknown host)"


def test_hosts_and_children_are_sorted_by_name():
    entries = [
        {"id": "1", "method": "GET", "url": "https://z.example.com/z", "response_status": 200},
        {"id": "2", "method": "GET", "url": "https://a.example.com/b", "response_status": 200},
        {"id": "3", "method": "GET", "url": "https://a.example.com/a", "response_status": 200},
    ]
    tree = main._build_site_map_tree(entries)["in_scope"]
    assert [h["name"] for h in tree] == ["a.example.com", "z.example.com"]
    assert [c["name"] for c in tree[0]["children"]] == ["a", "b"]


def test_leaf_display_name_is_the_final_path_segment_not_the_full_url():
    # OWASP ZAP's own Sites tree shows "GET:name", never the full URL, on a leaf row -- the
    # surrounding folders already spell out the path, so repeating it on every leaf is just noise.
    entries = [{"id": "1", "method": "GET", "url": "https://example.com/api/v1/users", "response_status": 200}]
    leaf = main._build_site_map_tree(entries)["in_scope"][0]["children"][0]["children"][0]["children"][0]["leaves"][0]
    assert leaf["name"] == "users"


def test_leaf_display_name_is_a_bare_slash_for_the_host_root():
    entries = [{"id": "1", "method": "GET", "url": "https://example.com/", "response_status": 200}]
    leaf = main._build_site_map_tree(entries)["in_scope"][0]["leaves"][0]
    assert leaf["name"] == "/"


def test_leaf_display_name_includes_a_real_query_string():
    # Two hits on the same path with different query parameters are two different things worth
    # telling apart at a glance, not collapsed into one indistinguishable "login" leaf.
    entries = [{"id": "1", "method": "GET", "url": "https://example.com/login?redirect=https://evil.com", "response_status": 200}]
    leaf = main._build_site_map_tree(entries)["in_scope"][0]["children"][0]["leaves"][0]
    assert leaf["name"] == "login?redirect=https://evil.com"


def test_leaf_display_name_truncates_a_very_long_query_string():
    entries = [{"id": "1", "method": "GET", "url": "https://example.com/x?" + "a" * 200, "response_status": 200}]
    leaf = main._build_site_map_tree(entries)["in_scope"][0]["children"][0]["leaves"][0]
    assert leaf["name"].startswith("x?" + "a" * 57 + "...")
    assert len(leaf["name"]) < 100


def test_scope_entries_splits_hosts_into_in_scope_and_other():
    entries = [
        {"id": "1", "method": "GET", "url": "https://target.example.com/a", "response_status": 200},
        {"id": "2", "method": "GET", "url": "https://fonts.gstatic.com/b", "response_status": 200},
    ]
    tree = main._build_site_map_tree(entries, ["target.example.com"])
    assert [h["name"] for h in tree["in_scope"]] == ["target.example.com"]
    assert [h["name"] for h in tree["other"]] == ["fonts.gstatic.com"]


def test_scope_entries_wildcard_covers_subdomains():
    entries = [
        {"id": "1", "method": "GET", "url": "https://api.example.com/a", "response_status": 200},
        {"id": "2", "method": "GET", "url": "https://unrelated.net/b", "response_status": 200},
    ]
    tree = main._build_site_map_tree(entries, ["*.example.com"])
    assert [h["name"] for h in tree["in_scope"]] == ["api.example.com"]
    assert [h["name"] for h in tree["other"]] == ["unrelated.net"]


def test_real_entries_are_confirmed_leaves():
    entries = [{"id": "1", "method": "GET", "url": "https://example.com/api/users", "response_status": 200}]
    leaf = main._build_site_map_tree(entries)["in_scope"][0]["children"][0]["children"][0]["leaves"][0]
    assert leaf["confirmed"] is True


def test_candidate_urls_become_unconfirmed_leaves_alongside_real_traffic():
    # The whole point: wayback_urls/common_crawl_urls discover real paths that were never actually
    # requested through the proxy or the agent's own browser -- these must still show up in the
    # tree, distinguishable from a real captured exchange, not silently dropped.
    entries = [{"id": "1", "method": "GET", "url": "https://example.com/api/users", "response_status": 200}]
    candidate_urls = ["https://example.com/api/orders", "https://example.com/admin/config"]
    tree = main._build_site_map_tree(entries, candidate_urls=candidate_urls)["in_scope"]
    host = tree[0]
    assert host["name"] == "example.com"
    api_node = next(c for c in host["children"] if c["name"] == "api")
    assert {c["name"] for c in api_node["children"]} == {"users", "orders"}
    users_leaf = next(c for c in api_node["children"] if c["name"] == "users")["leaves"][0]
    orders_leaf = next(c for c in api_node["children"] if c["name"] == "orders")["leaves"][0]
    assert users_leaf["confirmed"] is True
    assert orders_leaf["confirmed"] is False
    assert orders_leaf["id"] is None
    assert orders_leaf["method"] is None
    assert orders_leaf["status"] is None
    admin_node = next(c for c in host["children"] if c["name"] == "admin")
    assert admin_node["children"][0]["leaves"][0]["confirmed"] is False


def test_candidate_url_already_in_real_traffic_does_not_duplicate_the_leaf():
    # A URL wayback_urls/common_crawl_urls discovered that the agent (or the operator) has since
    # actually requested must show as ONE confirmed leaf, never a second, redundant unconfirmed one.
    entries = [{"id": "1", "method": "GET", "url": "https://example.com/api/users", "response_status": 200}]
    tree = main._build_site_map_tree(entries, candidate_urls=["https://example.com/api/users"])["in_scope"]
    api_node = tree[0]["children"][0]
    assert len(api_node["children"]) == 1
    users_node = api_node["children"][0]
    assert len(users_node["leaves"]) == 1
    assert users_node["leaves"][0]["confirmed"] is True


def test_candidate_urls_default_to_none_without_breaking_existing_callers():
    entries = [{"id": "1", "method": "GET", "url": "https://example.com/", "response_status": 200}]
    tree = main._build_site_map_tree(entries)["in_scope"]
    assert tree[0]["leaves"][0]["confirmed"] is True
