"""agent/llm_client.py's Settings-page API-key management: check_api_key (a token-free
models.list() probe, never a real chat completion), save_provider_api_key/clear_provider_api_key
(.env read-modify-write + os.environ mirror). Every exception branch must map to a static message
-- some providers echo the submitted key back inside an error body on malformed-auth responses, so
forwarding raw exception text would leak the key into the page the Settings UI's masking protects.
"""
import os

import httpx
import openai
import pytest

from agent import llm_client
from agent.llm_client import PROVIDER_REGISTRY, check_api_key, clear_provider_api_key, save_provider_api_key


class _FakeModels:
    def __init__(self, behavior):
        self._behavior = behavior
        self.captured_kwargs = None

    def list(self, **kwargs):
        self.captured_kwargs = kwargs
        if isinstance(self._behavior, Exception):
            raise self._behavior
        return self._behavior


class _FakeClient:
    def __init__(self, models):
        self.models = models


def _install_fake_openai(monkeypatch, behavior):
    fake_models = _FakeModels(behavior)
    monkeypatch.setattr(llm_client.openai, "OpenAI", lambda **kwargs: _FakeClient(fake_models))
    return fake_models


def _fake_response(status_code):
    request = httpx.Request("GET", "https://example.invalid/v1/models")
    return httpx.Response(status_code=status_code, request=request)


# --- check_api_key ---


def test_check_api_key_unknown_provider():
    result = check_api_key("not-a-real-provider", "whatever")
    assert result == {"ok": False, "message": "Unknown provider."}


@pytest.fixture
def provider_id():
    return next(iter(PROVIDER_REGISTRY))


def test_check_api_key_success_case(monkeypatch, provider_id):
    _install_fake_openai(monkeypatch, object())
    result = check_api_key(provider_id, "sk-some-key")
    assert result == {"ok": True, "message": "Key accepted."}


def test_check_api_key_maps_authentication_error_without_leaking_the_key(monkeypatch, provider_id):
    exc = openai.AuthenticationError("bad key: sk-real-secret-value", response=_fake_response(401), body=None)
    _install_fake_openai(monkeypatch, exc)
    result = check_api_key(provider_id, "sk-real-secret-value")
    assert result == {"ok": False, "message": "Rejected: authentication failed."}
    assert "sk-real-secret-value" not in result["message"]


def test_check_api_key_maps_permission_denied_error(monkeypatch, provider_id):
    exc = openai.PermissionDeniedError("nope", response=_fake_response(403), body=None)
    _install_fake_openai(monkeypatch, exc)
    result = check_api_key(provider_id, "sk-x")
    assert result == {"ok": False, "message": "Rejected: permission denied."}


def test_check_api_key_treats_not_found_as_inconclusive_not_failed(monkeypatch, provider_id):
    """A provider with no models-list route at all is not evidence the key is bad -- must not
    report ok=False just because this particular endpoint is missing."""
    exc = openai.NotFoundError("no such route", response=_fake_response(404), body=None)
    _install_fake_openai(monkeypatch, exc)
    result = check_api_key(provider_id, "sk-x")
    assert result["ok"] is True


def test_check_api_key_maps_connection_error(monkeypatch, provider_id):
    exc = openai.APIConnectionError(request=httpx.Request("GET", "https://example.invalid/v1/models"))
    _install_fake_openai(monkeypatch, exc)
    result = check_api_key(provider_id, "sk-x")
    assert result == {"ok": False, "message": "Could not reach the provider."}


def test_check_api_key_maps_generic_status_error_without_forwarding_raw_text(monkeypatch, provider_id):
    exc = openai.BadRequestError("body contains sk-real-secret-value somewhere", response=_fake_response(400), body=None)
    _install_fake_openai(monkeypatch, exc)
    result = check_api_key(provider_id, "sk-real-secret-value")
    assert result["ok"] is False
    assert "HTTP 400" in result["message"]
    assert "sk-real-secret-value" not in result["message"]


def test_check_api_key_omits_auth_header_when_key_is_blank(monkeypatch, provider_id):
    fake_models = _install_fake_openai(monkeypatch, object())
    check_api_key(provider_id, "")
    assert "extra_headers" in fake_models.captured_kwargs


def test_check_api_key_sends_no_header_override_when_key_is_provided(monkeypatch, provider_id):
    fake_models = _install_fake_openai(monkeypatch, object())
    check_api_key(provider_id, "sk-real-key")
    assert fake_models.captured_kwargs == {}


def test_check_api_key_blank_key_does_not_claim_a_key_was_accepted(monkeypatch, provider_id):
    """Real bug found via live UI testing: the Settings page's Test button on an empty field for
    an optional-key provider (opencode-zen — no key required at all) reached this same success
    path (the endpoint really is reachable with no Authorization header) and reported "Key
    accepted." -- misleading, since no credential was ever typed or sent. Only a genuinely
    non-empty api_key should ever earn that specific message."""
    _install_fake_openai(monkeypatch, object())
    result = check_api_key(provider_id, "")
    assert result["ok"] is True
    assert result["message"] != "Key accepted."
    assert "no key needed" in result["message"].lower()


# --- save_provider_api_key / clear_provider_api_key ---


def test_save_provider_api_key_writes_env_and_mirrors_to_os_environ(tmp_path, monkeypatch, provider_id):
    env_file = tmp_path / ".env"
    monkeypatch.setattr(llm_client, "_ENV_PATH", str(env_file))
    config = PROVIDER_REGISTRY[provider_id]
    monkeypatch.delenv(config.api_key_env, raising=False)

    save_provider_api_key(provider_id, "sk-newly-saved")

    assert os.environ[config.api_key_env] == "sk-newly-saved"
    assert env_file.exists()
    assert "sk-newly-saved" in env_file.read_text()


def test_clear_provider_api_key_removes_from_env_and_os_environ(tmp_path, monkeypatch, provider_id):
    env_file = tmp_path / ".env"
    monkeypatch.setattr(llm_client, "_ENV_PATH", str(env_file))
    config = PROVIDER_REGISTRY[provider_id]
    save_provider_api_key(provider_id, "sk-to-be-cleared")

    clear_provider_api_key(provider_id)

    assert config.api_key_env not in os.environ
    assert "sk-to-be-cleared" not in env_file.read_text()


def test_clear_provider_api_key_is_a_no_op_when_env_file_does_not_exist_yet(tmp_path, monkeypatch, provider_id):
    monkeypatch.setattr(llm_client, "_ENV_PATH", str(tmp_path / "does-not-exist.env"))
    clear_provider_api_key(provider_id)  # must not raise
