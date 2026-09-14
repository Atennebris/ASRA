"""web_self_register (agent/tools/native.py): a real, single-shot self-registration attempt
against a target's own signup form -- for the "no existing account at all" case, distinct from
default_creds_check (try known defaults) and hydra/web_login_bruteforce (crack an existing
account). Same real-httpx.MockTransport approach as test_authenticated_crawl_and_idor_probe.py.
"""
import httpx

from agent.tools import native

_RealHTTPXClient = httpx.Client  # captured before any test monkeypatches httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def test_missing_registration_path_is_an_error():
    result = native.web_self_register({"target": "https://example.com"})
    assert result["status"] == "error"
    assert "registration_path" in result["error"]


def test_missing_success_and_failure_string_is_an_error():
    result = native.web_self_register({"target": "https://example.com", "registration_path": "/register"})
    assert result["status"] == "error"
    assert "failure_string" in result["error"] or "success_string" in result["error"]


def test_successful_registration_returns_credentials_and_auto_generates_username_password(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, text="<form></form>")
        return httpx.Response(200, text="Welcome to your new account!")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.web_self_register({
        "target": "https://example.com", "registration_path": "/register",
        "success_string": "Welcome to your new account",
    })

    assert result["status"] == "ok"
    assert len(result["successful_credentials"]) == 1
    cred = result["successful_credentials"][0]
    assert cred["username"].startswith("asra_")
    assert cred["password"]
    assert result["registration_url"] == "https://example.com/register"
    assert result["login_url"] is None  # no login_path given -- no separate login step attempted


def test_registration_with_explicit_username_and_password_uses_them_verbatim(monkeypatch):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            seen["body"] = request.read().decode()
        return httpx.Response(200, text="Account created")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.web_self_register({
        "target": "https://example.com", "registration_path": "/signup",
        "username": "bob", "password": "S3cret!",
        "success_string": "Account created",
    })

    assert result["status"] == "ok"
    assert result["successful_credentials"] == [{"username": "bob", "password": "S3cret!"}]
    assert "bob" in seen["body"] and "S3cret" in seen["body"]


def test_registration_not_matching_success_string_is_reported_as_not_registered(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="Error: that username is taken")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.web_self_register({
        "target": "https://example.com", "registration_path": "/register",
        "success_string": "Welcome",
    })

    assert result["status"] == "error"
    assert "did not match" in result["error"]
    assert result["status_code"] == 200


def test_csrf_token_is_picked_up_from_the_registration_page_and_replayed(monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, text='<input type="hidden" name="csrf_token" value="tok-123">')
        captured["body"] = request.read().decode()
        return httpx.Response(200, text="Registered successfully")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.web_self_register({
        "target": "https://example.com", "registration_path": "/register",
        "success_string": "Registered successfully",
    })

    assert result["status"] == "ok"
    assert "csrf_token=tok-123" in captured["body"]


def test_login_path_performs_a_real_login_after_successful_registration(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/register":
            return httpx.Response(200, text="Welcome!")
        if request.url.path == "/login" and request.method == "POST":
            return httpx.Response(200, headers={"set-cookie": "sessionid=abc123; Path=/"}, text="logged in")
        return httpx.Response(200, text="")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.web_self_register({
        "target": "https://example.com", "registration_path": "/register", "login_path": "/login",
        "success_string": "Welcome!",
    })

    assert result["status"] == "ok"
    assert result["login_url"] == "https://example.com/login"
    assert result["cookie"] and "sessionid=abc123" in result["cookie"]


def test_login_path_failure_does_not_undo_a_successful_registration(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/register":
            return httpx.Response(200, text="Welcome!")
        if request.url.path == "/login":
            raise httpx.ConnectError("connection refused", request=request)
        return httpx.Response(200, text="")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.web_self_register({
        "target": "https://example.com", "registration_path": "/register", "login_path": "/login",
        "success_string": "Welcome!",
    })

    assert result["status"] == "ok"
    assert result["login_url"] is None  # login attempt failed -- registration result still stands


def test_extra_fields_are_included_in_the_registration_post(monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            captured["body"] = request.read().decode()
        return httpx.Response(200, text="Welcome!")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.web_self_register({
        "target": "https://example.com", "registration_path": "/register",
        "success_string": "Welcome!", "extra_fields": {"terms": "on"},
        "confirm_password_field": "password2", "password": "S3cret!",
    })

    assert result["status"] == "ok"
    assert "terms=on" in captured["body"]
    assert "password2=S3cret" in captured["body"]


def test_network_error_reaching_the_target_is_a_clean_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.web_self_register({
        "target": "https://unreachable.example.com", "registration_path": "/register",
        "success_string": "Welcome!",
    })

    assert result["status"] == "error"
