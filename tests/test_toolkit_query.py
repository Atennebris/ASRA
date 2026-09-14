"""agent/tools/toolkit_query.py -- the HTTPQL-lite parser/predicate engine backing both the
list_captured_traffic tool's own `query` parameter and the Site Map's manual filter box."""
import pytest

from agent.tools.toolkit_query import QuerySyntaxError, compile_query, filter_entries


def _entry(**overrides):
    base = {
        "method": "GET",
        "url": "https://example.com/login?x=1",
        "response_status": 200,
        "source": "proxy",
        "request_headers": {"Host": "example.com"},
        "response_headers": {"Content-Type": "text/html", "Set-Cookie": "sid=1; HttpOnly"},
        "request_body": "",
        "response_body": "ok",
        "flags": [],
    }
    base.update(overrides)
    return base


def test_simple_eq_matches():
    assert filter_entries([_entry(method="POST")], "method.eq:POST") == [_entry(method="POST")]
    assert filter_entries([_entry(method="GET")], "method.eq:POST") == []


def test_eq_is_case_insensitive():
    assert len(filter_entries([_entry(method="get")], "method.eq:GET")) == 1


def test_cont_substring():
    entries = [_entry(url="https://example.com/admin/users")]
    assert len(filter_entries(entries, "url.cont:admin")) == 1
    assert len(filter_entries(entries, "url.cont:nonexistent")) == 0


def test_ncont_negation():
    entries = [_entry(response_body="all good")]
    assert len(filter_entries(entries, 'resp.body.ncont:"error"')) == 1
    assert len(filter_entries(entries, 'resp.body.cont:"error"')) == 0


def test_like_wildcards():
    entries = [_entry(url="https://example.com/api/v1/users")]
    assert len(filter_entries(entries, 'url.like:"%api%users"')) == 1
    assert len(filter_entries(entries, 'url.like:"%zzz%"')) == 0


def test_regex_operator():
    entries = [_entry(url="https://example.com/user/1234")]
    assert len(filter_entries(entries, r'url.regex:"/user/\d+$"')) == 1
    assert len(filter_entries(entries, r'url.regex:"/user/[a-z]+$"')) == 0


def test_invalid_regex_raises_query_syntax_error():
    with pytest.raises(QuerySyntaxError):
        filter_entries([_entry()], "url.regex:(unclosed")


def test_host_and_path_derived_from_url():
    entries = [_entry(url="https://example.com/a/b?x=1")]
    assert len(filter_entries(entries, "host.eq:example.com")) == 1
    assert len(filter_entries(entries, "path.eq:/a/b")) == 1


def test_status_field():
    entries = [_entry(response_status=404)]
    assert len(filter_entries(entries, "status.eq:404")) == 1
    assert len(filter_entries(entries, "status.eq:200")) == 0


def test_header_name_and_value_search_across_all_headers():
    entries = [_entry(response_headers={"Content-Type": "text/html", "Set-Cookie": "sid=1"})]
    assert len(filter_entries(entries, 'resp.header.name.eq:"Set-Cookie"')) == 1
    assert len(filter_entries(entries, 'resp.header.value.cont:"sid="')) == 1
    assert len(filter_entries(entries, 'resp.header.value.cont:"nope"')) == 0


def test_bracketed_header_lookup_is_case_insensitive():
    entries = [_entry(request_headers={"Authorization": "Bearer abc"})]
    assert len(filter_entries(entries, 'req.header["authorization"].cont:"Bearer"')) == 1


def test_bracketed_header_missing_header_yields_empty_candidate_not_error():
    entries = [_entry(request_headers={})]
    assert len(filter_entries(entries, 'req.header["X-Missing"].eq:""')) == 1


def test_flags_field():
    entries = [_entry(flags=["sql_error", "reflected_payload"])]
    assert len(filter_entries(entries, "flags.cont:sql_error")) == 1
    assert len(filter_entries(entries, "flags.cont:open_redirect")) == 0


def test_and_requires_all_terms():
    entries = [_entry(method="POST", response_status=500)]
    assert len(filter_entries(entries, "method.eq:POST AND status.eq:500")) == 1
    assert len(filter_entries(entries, "method.eq:POST AND status.eq:200")) == 0


def test_or_requires_any_term():
    entries = [_entry(method="PUT")]
    assert len(filter_entries(entries, "method.eq:POST OR method.eq:PUT")) == 1


def test_and_binds_tighter_than_or():
    # method.eq:GET OR (method.eq:POST AND status.eq:500) -- a GET entry should match via the
    # first clause regardless of status, without needing explicit parentheses.
    entries = [_entry(method="GET", response_status=200)]
    assert len(filter_entries(entries, "method.eq:GET OR method.eq:POST AND status.eq:500")) == 1


def test_parentheses_override_precedence():
    entries = [_entry(method="GET", response_status=500)]
    assert len(filter_entries(entries, "(method.eq:GET OR method.eq:POST) AND status.eq:500")) == 1
    assert len(filter_entries(entries, "(method.eq:GET OR method.eq:POST) AND status.eq:200")) == 0


@pytest.mark.parametrize("bad_query", [
    "",
    "   ",
    "not a real query",
    "method.bogus_op:GET",
    "method.eq:GET AND",
    "(method.eq:GET",
    "method.eq:GET)",
    "method.eq:GET AND OR status.eq:200",
])
def test_malformed_queries_raise_query_syntax_error(bad_query):
    with pytest.raises(QuerySyntaxError):
        compile_query(bad_query)


def test_unknown_field_raises_query_syntax_error():
    with pytest.raises(QuerySyntaxError):
        filter_entries([_entry()], "nonexistent_field.eq:x")
