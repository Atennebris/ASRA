"""api_schema_discovery: a web API's whole surface is sometimes free -- a live GraphQL
introspection query or an exposed swagger/openapi spec leaks every real mutation/type/field/
endpoint at once. Real gap this closes: no existing tool ever checked for either (grep-confirmed
zero mentions of graphql/introspection/swagger/openapi anywhere in agent/ before this).
"""
import httpx

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools import native
from agent.tools.registry import get_tools_by_category

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def test_api_schema_discovery_is_registered_as_a_passive_scan_tool():
    scan_tools = {spec.name: spec for spec in get_tools_by_category("scan")}
    assert "api_schema_discovery" in scan_tools
    assert scan_tools["api_schema_discovery"].requires_allowed_target is False


def test_reports_graphql_introspection_when_the_schema_is_actually_returned(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/graphql":
            return httpx.Response(200, json={"data": {"__schema": {"types": [{"name": "User"}, {"name": "Query"}]}}})
        return httpx.Response(404)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.api_schema_discovery({"target": "https://api.example.com"})

    assert result["status"] == "ok"
    assert len(result["graphql_endpoints"]) == 1
    endpoint = result["graphql_endpoints"][0]
    assert endpoint["path"] == "/graphql"
    assert endpoint["introspection_enabled"] is True
    assert set(endpoint["sample_types"]) == {"User", "Query"}
    # No queryType/mutationType in this mock response -- must self-heal to empty lists, not KeyError.
    assert endpoint["queryable_fields"] == []
    assert endpoint["mutations"] == []


def test_reports_queryable_fields_and_mutations_with_their_arg_names(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/graphql":
            return httpx.Response(200, json={"data": {"__schema": {
                "queryType": {"fields": [{"name": "user", "args": [{"name": "id"}]}, {"name": "me", "args": []}]},
                "mutationType": {"fields": [{"name": "login", "args": [{"name": "username"}, {"name": "password"}]}]},
                "types": [{"name": "User"}],
            }}})
        return httpx.Response(404)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.api_schema_discovery({"target": "https://api.example.com"})

    endpoint = result["graphql_endpoints"][0]
    assert {"name": "user", "args": ["id"]} in endpoint["queryable_fields"]
    assert {"name": "me", "args": []} in endpoint["queryable_fields"]
    assert endpoint["mutations"] == [{"name": "login", "args": ["username", "password"]}]


def test_reports_no_graphql_endpoints_when_introspection_is_disabled_everywhere(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"errors": [{"message": "introspection is disabled"}]})
        return httpx.Response(404)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.api_schema_discovery({"target": "https://api.example.com"})

    assert result["status"] == "ok"
    assert result["graphql_endpoints"] == []


def test_reports_an_exposed_openapi_spec(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/swagger.json":
            return httpx.Response(200, text='{"swagger": "2.0", "paths": {}}')
        return httpx.Response(404)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.api_schema_discovery({"target": "https://api.example.com"})

    assert result["status"] == "ok"
    assert len(result["openapi_specs"]) == 1
    assert result["openapi_specs"][0]["path"] == "/swagger.json"
    assert result["openapi_specs"][0]["status_code"] == 200


def test_a_dead_path_is_silently_skipped_not_treated_as_an_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.api_schema_discovery({"target": "https://api.example.com"})

    assert result["status"] == "ok"
    assert result["graphql_endpoints"] == []
    assert result["openapi_specs"] == []
