"""url_declutter.declutter_urls (agent/tools/url_declutter.py) -- reimplementation of uro's own
dedup heuristics (s0md3v/uro, Apache-2.0), wired into wayback_urls/common_crawl_urls so those tools
hand back distinct attack surface instead of hundreds of near-identical archive snapshots.
"""
from agent.tools.url_declutter import declutter_urls


def test_drops_static_asset_urls():
    result = declutter_urls([
        "https://example.com/app.css",
        "https://example.com/logo.png",
        "https://example.com/page.html",
    ])

    assert result["urls"] == ["https://example.com/page.html"]
    assert result["removed_static_asset"] == 2
    assert result["removed_duplicate_shape"] == 0


def test_collapses_numeric_id_paths_to_one_representative():
    result = declutter_urls([
        "https://example.com/product/1",
        "https://example.com/product/2",
        "https://example.com/product/3",
    ])

    assert result["urls"] == ["https://example.com/product/1"]
    assert result["removed_duplicate_shape"] == 2


def test_collapses_hyphen_heavy_slugs_to_one_representative():
    result = declutter_urls([
        "https://example.com/blog/how-to-do-a-thing-with-code",
        "https://example.com/blog/another-long-post-title-here",
    ])

    assert result["urls"] == ["https://example.com/blog/how-to-do-a-thing-with-code"]
    assert result["removed_duplicate_shape"] == 1


def test_keeps_a_url_that_introduces_a_new_query_param_for_the_same_shape():
    result = declutter_urls([
        "https://example.com/page?id=1",
        "https://example.com/page?id=2",
        "https://example.com/page?id=3&debug=true",
    ])

    # id=2 repeats the exact param-name set already seen for this shape -- dropped.
    # debug=true introduces a genuinely new parameter name for this shape -- kept.
    assert result["urls"] == ["https://example.com/page?id=1", "https://example.com/page?id=3&debug=true"]
    assert result["removed_duplicate_shape"] == 1


def test_distinct_hosts_are_never_collapsed_together():
    result = declutter_urls([
        "https://a.example.com/item/1",
        "https://b.example.com/item/1",
    ])

    assert result["urls"] == ["https://a.example.com/item/1", "https://b.example.com/item/1"]
    assert result["removed_duplicate_shape"] == 0


def test_flags_urls_with_known_interesting_parameter_names():
    result = declutter_urls([
        "https://example.com/download?file=report.pdf",
        "https://example.com/profile?theme=dark",
    ])

    assert result["interesting_urls"] == ["https://example.com/download?file=report.pdf"]


def test_stats_reflect_raw_vs_kept_counts():
    result = declutter_urls([
        "https://example.com/a.css",
        "https://example.com/product/1",
        "https://example.com/product/2",
        "https://example.com/unique-page",
    ])

    assert result["raw_count"] == 4
    assert result["kept_count"] == 2
    assert result["removed_count"] == 2


def test_empty_input_returns_empty_result_with_zeroed_stats():
    result = declutter_urls([])

    assert result == {
        "urls": [],
        "raw_count": 0,
        "kept_count": 0,
        "removed_count": 0,
        "removed_static_asset": 0,
        "removed_duplicate_shape": 0,
        "interesting_urls": [],
    }
