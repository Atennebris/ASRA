"""agent/settings_transfer.py (Settings -> General -> Transfer settings) and its three thin routes in
main.py: a real export -> code -> decode -> preview -> apply round trip into an isolated app dir,
the with/without sensitive-data choice, passphrase sealing, and strict rejection of malformed or
hostile payloads with nothing changed.

tests/conftest.py already isolates APP_DATA_DIR and most *_STORE_PATH globals per test. The stores it
does not cover (sounds, the .env-backed launch screen / update switch / tool keys / sudo password) are
pointed at throwaway files here, and os.environ is restored afterwards because the real save_* functions
mirror secrets into this process's environment.
"""
import base64
import json
import os
import zlib

import pytest
from fastapi.testclient import TestClient

import main
from agent import intro_settings, settings_transfer as st, sound_settings, updater
from agent import custom_providers, settings as llm_settings_mod
from agent.custom_providers import create_custom_provider, load_custom_providers
from agent.intro_settings import load_launch_screen, save_launch_screen
from agent.llm_client import save_provider_api_key, save_provider_base_url
from agent.settings import (
    add_provider_to_list, load_llm_settings, save_fallback_chain_settings, save_llm_settings,
    save_secondary_verification_provider, set_free_models_only, set_provider_enabled,
)
from agent.sound_settings import save_master_sound_enabled, save_sound_event
from agent.timezone_settings import save_clock_show_date, save_clock_style, save_display_timezone
from agent.tools import capability_install, chat_settings_store, subagent_store, tool_api_keys, wordlist_catalog, wordlist_store
from agent.tools.capability_install import has_sudo_password, save_sudo_password
from agent.tools.chat_settings_store import (
    load_chat_settings, save_chat_settings, save_last_chat_llm, save_quick_chat_session_id,
)
from agent.tools.subagent_store import add_profile, load_subagent_profiles
from agent.tools.tool_api_keys import get_tool_api_key, save_tool_api_key
from agent.tools.toolkit_settings_store import load_toolkit_agent_settings, save_toolkit_agent_settings

SECRETS = ("qwen-key-SECRET", "custom-key-SECRET", "wpscan-key-SECRET", "sudo-pw-SECRET")
PASSPHRASE = "correct horse battery staple"
needs_crypto = pytest.mark.skipif(not st.ENCRYPTION_AVAILABLE, reason="cryptography is not installed")

_ENV_VARS_TOUCHED = ("QWEN_API_KEY", "OLLAMA_BASE_URL", "WPSCAN_API_KEY", "SUDO_PASSWORD")


@pytest.fixture(autouse=True)
def isolated_machine(tmp_path, monkeypatch):
    monkeypatch.setattr(sound_settings, "SETTINGS_PATH", tmp_path / "sounds.json")
    monkeypatch.setattr(intro_settings, "_ENV_PATH", str(tmp_path / "intro.env"))
    monkeypatch.setattr(updater, "_ENV_PATH", str(tmp_path / "updater.env"))
    monkeypatch.setattr(tool_api_keys, "_ENV_PATH", str(tmp_path / "tools.env"))
    monkeypatch.setattr(capability_install, "_ENV_PATH", str(tmp_path / "sudo.env"))
    wordlists_dir = tmp_path / "wordlists"
    wordlists_dir.mkdir()
    monkeypatch.setattr(wordlist_catalog, "_SCAN_ROOTS", (wordlists_dir,))
    saved_environ = dict(os.environ)
    for name in _ENV_VARS_TOUCHED:
        os.environ.pop(name, None)
    yield
    os.environ.clear()
    os.environ.update(saved_environ)


def _reset_caches():
    llm_settings_mod._settings_cache = None
    import agent.timezone_settings as tz
    tz._raw_cache = None


def _seed_source_machine(tmp_path) -> str:
    """A machine with every transferable thing set to a non-default value. Returns the custom provider id."""
    save_llm_settings("qwen", "qwen-plus")
    set_free_models_only(True)
    set_provider_enabled("mistral", False)
    add_provider_to_list("openrouter")
    save_secondary_verification_provider("mistral", "mistral-large-latest", True)
    custom = create_custom_provider("My Gateway", "https://gw.example.com/v1", api_key="custom-key-SECRET", model="gw-1")
    save_fallback_chain_settings(True, [{"provider": custom["id"], "model": "gw-1", "free_only": False}])
    save_provider_api_key("qwen", "qwen-key-SECRET")
    save_provider_base_url("ollama", "http://10.1.2.3:9999/v1")
    save_tool_api_key("wpscan", "wpscan-key-SECRET")
    save_sudo_password("sudo-pw-SECRET")
    save_display_timezone("Europe/Chisinau")
    save_clock_style("terminal")
    save_clock_show_date(True)
    save_master_sound_enabled(True)
    save_sound_event("finding", True, "ping")
    save_launch_screen("dragon")
    updater.save_update_check_on_startup(False)
    save_chat_settings(False, True, True, False)
    save_last_chat_llm(custom["id"], "gw-1", True)
    save_quick_chat_session_id("usr_quick_chat_123")
    save_toolkit_agent_settings({**load_toolkit_agent_settings(), "toolkit_proxy_enabled": False})
    add_profile("Recon helper", ["nmap"], "Map the host.", "qwen", "qwen-plus")
    wordlist = tmp_path / "wordlists" / "common.txt"
    wordlist.write_text("admin\nlogin\n")
    wordlist_store.set_assignment("ffuf", str(wordlist))
    _reset_caches()
    return custom["id"]


def _wipe_machine(tmp_path):
    """Back to a fresh install: every store file and every env file removed, secrets out of os.environ."""
    from agent import llm_client
    from agent.tools import toolkit_settings_store
    import agent.timezone_settings as tz
    for path in (
        llm_settings_mod.SETTINGS_PATH, custom_providers.CUSTOM_PROVIDERS_PATH, sound_settings.SETTINGS_PATH,
        tz.SETTINGS_PATH, chat_settings_store.CHAT_SETTINGS_STORE_PATH,
        toolkit_settings_store.TOOLKIT_AGENT_SETTINGS_STORE_PATH, subagent_store.SUBAGENT_STORE_PATH,
        wordlist_store.WORDLIST_STORE_PATH,
    ):
        path.unlink(missing_ok=True)
    for env_file in (llm_client._ENV_PATH, intro_settings._ENV_PATH, updater._ENV_PATH, tool_api_keys._ENV_PATH, capability_install._ENV_PATH):
        open(env_file, "w").close()
    for name in _ENV_VARS_TOUCHED:
        os.environ.pop(name, None)
    # The receiving machine has the same wordlist under a DIFFERENT absolute path.
    (tmp_path / "wordlists" / "common.txt").unlink()
    moved = tmp_path / "wordlists" / "sub"
    moved.mkdir()
    (moved / "common.txt").write_text("admin\n")
    _reset_caches()
    return moved / "common.txt"


def _snapshot():
    _reset_caches()
    return {section.id: section.loader() for section in st.SECTIONS}, dict(os.environ)


def _payload(sections=None, **extra):
    payload = {st.VERSION_FIELD: st.SETTINGS_VERSION, "sections": sections or {"display": {"show_clock": False}}}
    payload.update(extra)
    return payload


def _code(payload):
    return st.encode_code(payload)


# ---- round trip ------------------------------------------------------------------------------------


def test_round_trip_without_sensitive_data_restores_every_transferable_setting(tmp_path):
    custom_id = _seed_source_machine(tmp_path)
    code = st.encode_code(st.export_settings())
    new_wordlist = _wipe_machine(tmp_path)

    summary = st.preview_input(code)
    assert summary["has_sensitive"] is False
    assert {s["id"] for s in summary["sections"]} >= {"llm", "custom_providers", "display", "sounds", "chat", "subagents", "wordlists"}

    results = st.apply_input(code)
    assert results and all(r["status"] == "applied" for r in results)
    _reset_caches()

    llm = load_llm_settings()
    assert (llm["provider"], llm["model"], llm["free_models_only"]) == ("qwen", "qwen-plus", True)
    assert llm["disabled_providers"] == ["mistral"] and llm["added_providers"] == ["openrouter"]
    assert llm["secondary_verification_provider"] == "mistral" and llm["secondary_verification_free_only"] is True
    assert llm["fallback_chain_enabled"] is True and llm["fallback_chain"][0]["provider"] == custom_id

    [provider] = load_custom_providers()
    assert (provider["id"], provider["name"], provider["base_url"], provider["model"]) == (custom_id, "My Gateway", "https://gw.example.com/v1", "gw-1")
    assert provider["api_key"] == ""  # the key is sensitive: not carried without the opt-in
    assert os.environ.get("OLLAMA_BASE_URL") == "http://10.1.2.3:9999/v1"

    assert sound_settings.load_sound_settings()["events"]["finding"] == {"enabled": True, "sound": "ping"}
    assert load_launch_screen() == "dragon" and updater.load_update_check_on_startup() is False
    chat = load_chat_settings()
    assert (chat["web_fetch_enabled"], chat["browser_enabled"], chat["dork_engine_enabled"]) == (False, True, False)
    assert (chat["last_provider"], chat["last_model"], chat["last_free_only"]) == (custom_id, "gw-1", True)
    assert chat["quick_chat_session_id"] is None
    assert load_toolkit_agent_settings()["toolkit_proxy_enabled"] is False
    recon = next(p for p in load_subagent_profiles()["profiles"] if p["name"] == "Recon helper")
    assert recon["enabled"] is False and recon["allowed_tools"] == ["nmap"]
    assert wordlist_store.get_assigned_wordlist("ffuf") == str(new_wordlist)


def test_code_and_file_forms_import_identically():
    save_clock_style("digital")
    payload = st.export_settings()
    file_text = json.dumps(payload, indent=2)
    assert st.preview_input(file_text) == st.preview_input(st.encode_code(payload))


def test_code_tolerates_whitespace_and_line_wrapping_from_a_chat_or_email():
    payload = st.export_settings()
    code = st.encode_code(payload)
    wrapped = "\n  ".join(code[i:i + 60] for i in range(0, len(code), 60))
    assert st.decode_code(wrapped) == payload


# ---- sensitive data --------------------------------------------------------------------------------


def test_default_export_contains_no_sensitive_data(tmp_path):
    _seed_source_machine(tmp_path)
    payload = st.export_settings()
    for blob in (json.dumps(payload), st.encode_code(payload), json.dumps(st.decode_code(st.encode_code(payload)))):
        for secret in SECRETS:
            assert secret not in blob
    assert "sensitive" not in payload
    assert "tool_api_keys" not in payload["sections"] and "sudo" not in payload["sections"]


def test_sensitive_values_travel_only_when_chosen_and_unencrypted_without_passphrase(tmp_path):
    _seed_source_machine(tmp_path)
    payload = st.export_settings(include_sensitive=True)
    assert payload["sensitive"]["encrypted"] is False
    blob = json.dumps(payload)
    assert all(secret in blob for secret in SECRETS)

    code = st.encode_code(payload)
    _wipe_machine(tmp_path)
    assert st.preview_input(code)["sensitive_sections"]
    assert all(r["status"] == "applied" for r in st.apply_input(code, include_sensitive=True))
    assert os.environ["QWEN_API_KEY"] == "qwen-key-SECRET"
    assert get_tool_api_key("wpscan") == "wpscan-key-SECRET"
    assert has_sudo_password() and os.environ["SUDO_PASSWORD"] == "sudo-pw-SECRET"
    assert load_custom_providers()[0]["api_key"] == "custom-key-SECRET"


def test_owner_can_decline_sensitive_data_at_import_time(tmp_path):
    _seed_source_machine(tmp_path)
    code = st.encode_code(st.export_settings(include_sensitive=True))
    _wipe_machine(tmp_path)
    st.apply_input(code, include_sensitive=False)
    assert "QWEN_API_KEY" not in os.environ and not has_sudo_password()
    assert get_tool_api_key("wpscan") is None


@needs_crypto
def test_passphrase_seals_the_sensitive_block(tmp_path):
    _seed_source_machine(tmp_path)
    payload = st.export_settings(include_sensitive=True, passphrase=PASSPHRASE)
    block = payload["sensitive"]
    assert block["encrypted"] is True and block["kdf"] == "pbkdf2-hmac-sha256" and block["salt"]
    for blob in (json.dumps(payload), st.encode_code(payload)):
        assert not any(secret in blob for secret in SECRETS)
    assert st.export_settings(include_sensitive=True, passphrase=PASSPHRASE)["sensitive"]["salt"] != block["salt"]

    code = st.encode_code(payload)
    locked = st.preview_input(code)
    assert locked["has_sensitive"] and locked["sensitive_encrypted"] and locked["sensitive_sections"] is None
    assert st.preview_input(code, PASSPHRASE)["sensitive_sections"]

    _wipe_machine(tmp_path)
    assert all(r["status"] == "applied" for r in st.apply_input(code, PASSPHRASE, include_sensitive=True))
    assert os.environ["SUDO_PASSWORD"] == "sudo-pw-SECRET"


@needs_crypto
def test_wrong_or_missing_passphrase_is_rejected_and_changes_nothing(tmp_path):
    _seed_source_machine(tmp_path)
    code = st.encode_code(st.export_settings(include_sensitive=True, passphrase=PASSPHRASE))
    _wipe_machine(tmp_path)
    before = _snapshot()
    with pytest.raises(st.SettingsTransferError, match="Wrong passphrase"):
        st.apply_input(code, "not the passphrase", include_sensitive=True)
    with pytest.raises(st.SettingsTransferError, match="enter the passphrase"):
        st.apply_input(code, None, include_sensitive=True)
    assert _snapshot() == before


@needs_crypto
def test_tampered_ciphertext_is_rejected(tmp_path):
    _seed_source_machine(tmp_path)
    payload = st.export_settings(include_sensitive=True, passphrase=PASSPHRASE)
    token = payload["sensitive"]["token"]
    payload["sensitive"]["token"] = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    with pytest.raises(st.SettingsTransferError, match="Wrong passphrase, or the encrypted block was modified"):
        st.validate_payload(payload, passphrase=PASSPHRASE)


@needs_crypto
@pytest.mark.parametrize("iterations", [1, 50_000_000, True, "600000"])
def test_hostile_kdf_parameters_are_rejected(iterations):
    payload = st.export_settings(include_sensitive=True, passphrase=PASSPHRASE)
    payload.setdefault("sensitive", {"encrypted": True, "kdf": st.KDF_NAME, "salt": "AA", "token": "x"})["iterations"] = iterations
    with pytest.raises(st.SettingsTransferError):
        st.validate_payload(payload, passphrase=PASSPHRASE)


def test_passphrase_without_sensitive_opt_in_does_not_pretend_to_protect_anything(tmp_path):
    _seed_source_machine(tmp_path)
    assert "sensitive" not in st.export_settings(include_sensitive=False, passphrase=PASSPHRASE)


def test_passphrase_is_refused_when_cryptography_is_unavailable(monkeypatch, tmp_path):
    _seed_source_machine(tmp_path)
    monkeypatch.setattr(st, "ENCRYPTION_AVAILABLE", False)
    with pytest.raises(st.SettingsTransferError, match="cryptography"):
        st.export_settings(include_sensitive=True, passphrase=PASSPHRASE)
    # The only honest alternative is the explicit unencrypted export, never a fake "encryption".
    assert st.export_settings(include_sensitive=True)["sensitive"]["encrypted"] is False


# ---- machine-specific values -----------------------------------------------------------------------


def test_machine_specific_values_are_never_exported_even_in_sensitive_mode(tmp_path):
    _seed_source_machine(tmp_path)
    payload = st.export_settings(include_sensitive=True)
    blob = json.dumps(payload)
    assert "usr_quick_chat_123" not in blob and "quick_chat_session_id" not in blob
    assert str(tmp_path) not in blob and "/wordlists/" not in blob  # no absolute path of any kind
    assert payload["sections"]["wordlists"]["assignments"] == {"ffuf": "common.txt"}
    assert "created_at" not in json.dumps(payload["sections"].get("custom_providers", {}))
    assert not any(name in blob for name in ("codex", "copilot", "allowed_targets", "tool_paths"))


def test_registry_filter_drops_keys_a_loader_returns_but_the_registry_does_not_name(monkeypatch):
    chat = st.SECTIONS_BY_ID["chat"]
    monkeypatch.setattr(st, "SECTIONS", tuple(
        st.Section(s.id, s.label, s.keys, lambda: {**load_chat_settings(), "new_private_field": "leak"}, s.saver) if s.id == "chat" else s
        for s in st.SECTIONS
    ))
    assert "new_private_field" not in json.dumps(st.export_settings())
    assert chat.keys  # the registry itself is untouched


def test_wordlist_missing_on_the_target_is_skipped_with_a_note():
    payload = _payload({"wordlists": {"assignments": {"ffuf": "not-installed.txt"}}})
    [result] = st.apply_settings(st.validate_payload(payload), include_sensitive=False)
    assert result["status"] == "applied" and "not-installed.txt" in result["detail"]
    assert wordlist_store.get_assigned_wordlist("ffuf") is None


# ---- rejection: malformed or hostile payloads change nothing --------------------------------------


def _bomb_code():
    huge = b'{"x":"' + b"a" * (st.MAX_PAYLOAD_BYTES * 20) + b'"}'
    return st.CODE_PREFIX + base64.urlsafe_b64encode(zlib.compress(huge, 9)).decode().rstrip("=")


def _bad_inputs():
    good = st.encode_code(_payload({"display": {"show_clock": False}}))
    return {
        "empty": "",
        "not_a_code": "hello world",
        "oversized_code": st.CODE_PREFIX + "A" * st.MAX_CODE_CHARS,
        "decompression_bomb": _bomb_code(),
        "truncated_code": good[: len(good) // 2],
        "garbage_base64": st.CODE_PREFIX + "!!!!not-base64!!!!",
        "json_array": json.dumps([1, 2, 3]),
        "invalid_json": "{not json",
        "no_version": json.dumps({"sections": {}}),
        "future_version": json.dumps(_payload(**{st.VERSION_FIELD: 2})),
        "boolean_version": json.dumps(_payload(**{st.VERSION_FIELD: True})),
        "unknown_top_level_field": json.dumps(_payload(rm_rf="/")),
        "unknown_section": json.dumps(_payload({"shell": {"cmd": "id"}})),
        "unknown_key": json.dumps(_payload({"display": {"show_clock": False, "evil": 1}})),
        "wrong_type": json.dumps(_payload({"display": {"show_clock": "yes"}})),
        "bad_timezone": json.dumps(_payload({"display": {"timezone": "Mars/Olympus"}})),
        "sensitive_key_in_public_block": json.dumps(_payload({"builtin_providers": {"api_keys": {"qwen": "k"}}})),
        "path_in_wordlist_name": json.dumps(_payload({"wordlists": {"assignments": {"ffuf": "/etc/passwd"}}})),
        "dangling_custom_provider": json.dumps(_payload({"llm": {"provider": "custom-nope", "model": "m"}})),
        "newline_injection_in_secret": json.dumps(_payload(sensitive={"encrypted": False, "data": {"sudo": {"sudo_password": "x\nSUDO_PASSWORD=y"}}})),
        "public_key_in_sensitive_block": json.dumps(_payload(sensitive={"encrypted": False, "data": {"display": {"show_clock": True}}})),
        "malformed_sensitive_block": json.dumps(_payload(sensitive="please")),
    }


@pytest.mark.parametrize("name", list(_bad_inputs()))
def test_bad_payload_is_rejected_with_a_message_and_changes_nothing(name, tmp_path):
    _seed_source_machine(tmp_path)
    before = _snapshot()
    with pytest.raises(st.SettingsTransferError) as caught:
        st.apply_input(_bad_inputs()[name], include_sensitive=True)
    assert str(caught.value)
    assert _snapshot() == before
    with pytest.raises(st.SettingsTransferError):
        st.preview_input(_bad_inputs()[name])


def test_one_bad_section_rejects_the_whole_payload_even_if_other_sections_are_valid(tmp_path):
    _seed_source_machine(tmp_path)
    before = _snapshot()
    payload = _payload({"display": {"show_clock": False}, "sounds": {"master_enabled": "loud"}})
    with pytest.raises(st.SettingsTransferError):
        st.apply_input(json.dumps(payload))
    assert _snapshot() == before


def test_rejection_messages_never_echo_payload_values():
    payload = _payload({"display": {"show_clock": "SUPER-SECRET-VALUE"}})
    with pytest.raises(st.SettingsTransferError) as caught:
        st.apply_input(json.dumps(payload))
    assert "SUPER-SECRET-VALUE" not in str(caught.value)


def test_a_failing_section_is_rolled_back_and_the_others_still_apply(monkeypatch):
    save_display_timezone("UTC")
    save_clock_style("minimal")
    _reset_caches()
    real_save_date = st.save_clock_show_date
    calls = {"n": 0}

    def fail_first_call(show):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("disk full: leaked-value-123")
        real_save_date(show)

    monkeypatch.setattr(st, "save_clock_show_date", fail_first_call)
    payload = _payload({
        "display": {"timezone": "Europe/Chisinau", "clock_style": "terminal", "show_date": True},
        "sounds": {"master_enabled": True},
    })
    results = {r["id"]: r for r in st.apply_input(json.dumps(payload))}

    assert results["display"]["status"] == "failed" and "restored" in results["display"]["detail"]
    assert "leaked-value-123" not in json.dumps(results)
    assert results["sounds"]["status"] == "applied"
    _reset_caches()
    display = st.SECTIONS_BY_ID["display"].loader()
    assert display["timezone"] == "UTC" and display["clock_style"] == "minimal"
    assert sound_settings.load_sound_settings()["master_enabled"] is True


# ---- routes ----------------------------------------------------------------------------------------


def test_routes_round_trip_through_the_web_layer(tmp_path):
    _seed_source_machine(tmp_path)
    client = TestClient(main.app)

    exported = client.post("/api/settings/transfer/export", data={"include_sensitive": "false"})
    assert exported.status_code == 200
    body = exported.json()
    assert body["ok"] and body["code"].startswith(st.CODE_PREFIX) and body["filename"].endswith(".json")
    assert body["sensitive_included"] is False and body["sections"]
    assert not any(secret in exported.text for secret in SECRETS)
    assert json.loads(body["file_json"])[st.VERSION_FIELD] == st.SETTINGS_VERSION

    _wipe_machine(tmp_path)
    preview = client.post("/api/settings/transfer/preview", data={"data": body["code"]})
    assert preview.status_code == 200 and preview.json()["preview"]["sections"]

    applied = client.post("/api/settings/transfer/apply", data={"data": body["file_json"]})
    assert applied.status_code == 200 and applied.json()["ok"] is True
    _reset_caches()
    assert load_llm_settings()["provider"] == "qwen"


def test_routes_export_with_sensitive_choice(tmp_path):
    _seed_source_machine(tmp_path)
    client = TestClient(main.app)
    plain = client.post("/api/settings/transfer/export", data={"include_sensitive": "true"}).json()
    assert plain["sensitive_included"] and not plain["encrypted"]
    if st.ENCRYPTION_AVAILABLE:
        sealed = client.post("/api/settings/transfer/export", data={"include_sensitive": "true", "passphrase": PASSPHRASE})
        assert sealed.json()["encrypted"] is True
        assert not any(secret in sealed.text for secret in SECRETS)


def test_routes_reject_bad_input_with_400_and_a_message(tmp_path):
    _seed_source_machine(tmp_path)
    before = _snapshot()
    client = TestClient(main.app)
    for path in ("preview", "apply"):
        resp = client.post(f"/api/settings/transfer/{path}", data={"data": "ASRA1:definitely-not-valid"})
        assert resp.status_code == 400
        assert resp.json()["ok"] is False and resp.json()["error"]
    assert _snapshot() == before


def test_route_export_reports_a_passphrase_that_cannot_be_honoured(monkeypatch):
    monkeypatch.setattr(st, "ENCRYPTION_AVAILABLE", False)
    resp = TestClient(main.app).post("/api/settings/transfer/export", data={"include_sensitive": "true", "passphrase": "x"})
    assert resp.status_code == 400 and "cryptography" in resp.json()["error"]


def test_settings_page_renders_the_transfer_card_and_dialogs():
    html = TestClient(main.app).get("/settings").text
    assert "Transfer settings" in html
    assert 'data-transfer-open="export"' in html and 'data-transfer-open="import"' in html
    assert 'id="settings-export-dialog"' in html and 'id="settings-import-dialog"' in html
    assert "Export without sensitive data" in html
    assert "Export including API keys and sudo password" in html
    assert "settings_transfer.js" in html
    # The card is in the General tab body; the dialogs sit outside every tab section.
    general = html.split('data-settings-tab="general"', 1)[1].split('data-settings-tab="customization"', 1)[0]
    assert 'id="settings-transfer-card"' in general and 'id="settings-export-dialog"' not in general
    banner = html.split("settings-tabs", 1)[0]
    assert "data-transfer-open" not in banner  # never on the decorative page header


def test_settings_page_without_cryptography_hides_the_passphrase_field(monkeypatch):
    monkeypatch.setitem(main.templates.env.globals, "settings_transfer_encryption_available", False)
    html = TestClient(main.app).get("/settings").text
    assert 'id="transfer-export-passphrase" type="hidden"' in html
    assert "NOT encrypted" in html
    monkeypatch.setitem(main.templates.env.globals, "settings_transfer_encryption_available", True)
    html = TestClient(main.app).get("/settings").text
    assert 'id="transfer-export-passphrase" type="password"' in html


def test_transfer_ui_has_no_emoji():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for rel in ("templates/partials/settings_transfer_card.html", "templates/partials/settings_transfer_dialogs.html", "static/js/settings_transfer.js"):
        text = open(os.path.join(root, rel), encoding="utf-8").read()
        assert not [ch for ch in text if ord(ch) > 0x2000 and ch not in "…"], rel
