"""Regression coverage for native.py's http_request still wiring its passive-detector fields
(reflected_payload_detected/sql_error_detected/open_redirect_detected/command_injection_detected)
correctly end-to-end after the detectors themselves moved out to agent/tools/passive_detectors.py
(see that module's own docstring for why -- toolkit_store.py needed to reuse them without a
circular import). No such end-to-end test existed before this move; added here specifically to
catch a regression in the call-site wiring (argument mapping, the open_redirect hop-list adapter)
that a passive_detectors-only unit test (tests/test_passive_detectors.py) can't see."""
import httpx

from agent.tools.native import http_request

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def test_http_request_surfaces_reflected_payload_detection(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="echo: <script>alert(1)</script>")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = http_request({"target": "https://example.test/search?q=<script>alert(1)</script>"})

    assert result["status"] == "ok"
    assert result["reflected_payload_detected"] == {"param": "q", "value": "<script>alert(1)</script>"}
    # http_request only adds a *_detected key when that detector actually fired (native.py's own
    # "for field, value in detectors.items(): if value is not None: result[field] = value") -- a
    # miss is an absent key, not a present key holding None.
    assert "sql_error_detected" not in result
    assert "command_injection_detected" not in result


def test_http_request_surfaces_sql_error_detection(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="You have an error in your SQL syntax near ''")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = http_request({"target": "https://example.test/item?id=1'"})

    assert result["status"] == "ok"
    assert result["sql_error_detected"]["engine"] == "mysql"


def test_http_request_surfaces_command_injection_detection(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = http_request({"target": "https://example.test/x?f=../etc/passwd"})

    assert result["status"] == "ok"
    assert result["command_injection_detected"]["signature"] == "etc_passwd"


def test_http_request_surfaces_open_redirect_detection_via_response_history(monkeypatch):
    # A real, two-hop exchange (302 -> 200) so httpx.Client's OWN redirect-following logic
    # populates resp.history itself -- setting .history by hand on a single mocked response doesn't
    # work here: httpx.Client.send() recomputes history from its own redirect loop and overwrites
    # whatever a transport handler set directly, since (from the client's point of view) a single
    # 200 response never redirected at all.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/go":
            # A genuine open redirect: the server blindly echoes the "redirect" query param
            # straight into the Location header -- exactly the pattern detect_open_redirect looks
            # for (the param's real, unmodified value ending up as the actual redirect target).
            target = dict(request.url.params)["redirect"]
            return httpx.Response(302, headers={"location": target})
        return httpx.Response(200, text="landed")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = http_request({"target": "https://example.test/go?redirect=https://evil.example"})

    assert result["status"] == "ok"
    assert result["open_redirect_detected"] == {
        "param": "redirect", "value": "https://evil.example", "location": "https://evil.example",
    }


def test_http_request_all_detectors_none_for_a_clean_response(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>all good</html>")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = http_request({"target": "https://example.test/"})

    assert result["status"] == "ok"
    assert "reflected_payload_detected" not in result
    assert "sql_error_detected" not in result
    assert "open_redirect_detected" not in result
    assert "command_injection_detected" not in result
