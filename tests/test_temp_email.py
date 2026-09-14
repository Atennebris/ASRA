"""temp_email_create / temp_email_check_inbox (agent/tools/native.py): a real disposable-inbox
provider chain (mail.tm -> 1secmail -> guerrillamail) for a signup flow (web_self_register) that
needs a receivable email address. Same real-httpx.MockTransport approach as
test_web_self_register.py -- each provider gets its own mocked handler so the fallback chain can
be exercised deterministically (a provider going down mid-run is exactly the confirmed-live
scenario this chain exists for).
"""
import httpx

from agent.tools import native

_RealHTTPXClient = httpx.Client  # captured before any test monkeypatches httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def setup_function():
    native._temp_email_accounts.clear()


def _mailtm_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/domains":
        return httpx.Response(200, json={"hydra:member": [{"domain": "example-mail.test", "isActive": True}]})
    if request.url.path == "/accounts":
        return httpx.Response(201, json={"address": "someone@example-mail.test"})
    if request.url.path == "/token":
        return httpx.Response(200, json={"token": "fake-jwt-token"})
    if request.url.path == "/messages" and request.method == "GET":
        return httpx.Response(200, json={"hydra:member": [{"id": "msg1"}]})
    if request.url.path == "/messages/msg1":
        return httpx.Response(200, json={
            "from": {"address": "noreply@target.example"}, "subject": "Verify your account",
            "text": "Click here to verify: https://target.example/verify?token=abc123",
            "createdAt": "2026-01-01T00:00:00+00:00",
        })
    return httpx.Response(404)


def test_temp_email_create_uses_mailtm_when_it_works(monkeypatch):
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_mailtm_handler))

    result = native.temp_email_create({"_session_id": "usr_temp_mail"})

    assert result["status"] == "ok"
    assert result["provider"] == "mail.tm"
    assert result["email"].endswith("@example-mail.test")


def test_temp_email_check_inbox_returns_the_real_verification_text(monkeypatch):
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_mailtm_handler))
    native.temp_email_create({"_session_id": "usr_temp_mail_2"})

    result = native.temp_email_check_inbox({"_session_id": "usr_temp_mail_2"})

    assert result["status"] == "ok"
    assert result["provider"] == "mail.tm"
    assert len(result["messages"]) == 1
    assert "verify?token=abc123" in result["messages"][0]["text"]
    assert result["messages"][0]["from"] == "noreply@target.example"


def test_temp_email_check_inbox_requires_a_prior_create_call():
    result = native.temp_email_check_inbox({"_session_id": "usr_never_created"})
    assert result["status"] == "error"
    assert "temp_email_create" in result["error"]


def test_temp_email_create_falls_back_to_1secmail_when_mailtm_is_down(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if "mail.tm" in str(request.url):
            return httpx.Response(500, text="mail.tm is down")
        if "1secmail" in str(request.url):
            return httpx.Response(200, json=["random123@1secmail.test"])
        return httpx.Response(404)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.temp_email_create({"_session_id": "usr_fallback_1secmail"})

    assert result["status"] == "ok"
    assert result["provider"] == "1secmail"
    assert result["email"] == "random123@1secmail.test"


def test_temp_email_create_falls_back_to_guerrillamail_when_the_first_two_fail(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if "mail.tm" in str(request.url):
            return httpx.Response(500, text="mail.tm is down")
        if "1secmail" in str(request.url):
            return httpx.Response(403, text="Forbidden")
        if "guerrillamail" in str(request.url):
            return httpx.Response(200, json={"email_addr": "random@guerrillamailblock.com", "sid_token": "tok-1"})
        return httpx.Response(404)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.temp_email_create({"_session_id": "usr_fallback_guerrilla"})

    assert result["status"] == "ok"
    assert result["provider"] == "guerrillamail"
    assert result["email"] == "random@guerrillamailblock.com"


def test_temp_email_create_reports_a_browser_fallback_hint_when_every_provider_fails(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="down")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.temp_email_create({"_session_id": "usr_all_down"})

    assert result["status"] == "error"
    assert "mail.tm" in result["error"] and "1secmail" in result["error"] and "guerrillamail" in result["error"]
    assert "browser_navigate" in result["browser_fallback_hint"]


def test_temp_email_check_inbox_reads_from_guerrillamail_when_that_was_the_provider(monkeypatch):
    def create_handler(request: httpx.Request) -> httpx.Response:
        if "mail.tm" in str(request.url):
            return httpx.Response(500, text="down")
        if "1secmail" in str(request.url):
            return httpx.Response(403, text="Forbidden")
        return httpx.Response(200, json={"email_addr": "random@guerrillamailblock.com", "sid_token": "tok-2"})

    def check_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"list": [{
            "mail_from": "noreply@target.example", "mail_subject": "Your code",
            "mail_body": "Your verification code is 482913", "mail_date": "12:00:00",
        }]})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(create_handler))
    native.temp_email_create({"_session_id": "usr_guerrilla_check"})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(check_handler))
    result = native.temp_email_check_inbox({"_session_id": "usr_guerrilla_check"})

    assert result["status"] == "ok"
    assert result["provider"] == "guerrillamail"
    assert "482913" in result["messages"][0]["text"]


def test_temp_email_create_requires_session_context():
    result = native.temp_email_create({})
    assert result["status"] == "error"
    assert "session context" in result["error"]
