"""main.py's _group_technology_tokens (Jinja filter "group_tech_tokens") -- WhatWeb's own raw
output is a flat "Plugin[value1,value2]" (or bare "Plugin") token list, repeated verbatim across
every whatweb call made against the same host this session. The Recon tab used to just comma-join
the whole raw list as-is; this groups by plugin/header name, deduplicating values across repeats,
real "what does this run" signal sorted ahead of generic transport noise.
"""
import main


def test_groups_and_dedupes_repeated_tokens_across_multiple_calls():
    tokens = [
        "HTTPServer[cloudflare]", "Cookies[__cf_bm]",
        "HTTPServer[cloudflare]", "Cookies[__cf_bm]",  # same host, a second whatweb call
    ]
    result = dict(main._group_technology_tokens(tokens))
    assert result["HTTPServer"] == "cloudflare"
    assert result["Cookies"] == "__cf_bm"


def test_merges_distinct_values_for_the_same_plugin_name():
    tokens = ["Cookies[__cf_bm]", "Cookies[_cfuvid]"]
    result = dict(main._group_technology_tokens(tokens))
    assert result["Cookies"] == "__cf_bm, _cfuvid"


def test_handles_a_bare_token_with_no_bracketed_value():
    tokens = ["HTML5"]
    result = dict(main._group_technology_tokens(tokens))
    assert result["HTML5"] == ""


def test_sorts_real_signal_before_generic_transport_noise():
    tokens = ["Country[US]", "WordPress[6.4]", "IP[1.2.3.4]", "PHP[8.1]"]
    names = [name for name, _ in main._group_technology_tokens(tokens)]
    assert names.index("WordPress") < names.index("Country")
    assert names.index("PHP") < names.index("IP")


def test_empty_input_returns_empty_list():
    assert main._group_technology_tokens([]) == []
    assert main._group_technology_tokens(None) == []
