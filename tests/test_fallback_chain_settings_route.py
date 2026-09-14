"""main.py's Settings -> Reserve providers route (POST /api/settings/fallback-chain) -- the
operator-authored, opt-in LLM fallback chain built entirely from real (provider, model) dropdown
rows, not free text. Neither this nor /api/settings/llm has a ToolSpec registration -- the LLM
agent can never reach either, only the operator clicking the Settings UI.
"""
import json
import re
import time
from urllib.parse import urlencode

import jinja2
from fastapi.testclient import TestClient

import main

_FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}
# Captured at collection time, before conftest.py's own autouse fixture stubs
# main._reachable_local_provider_ids out for every test -- the one test in this file that
# exercises the REAL implementation (not just the higher-level context functions that consume it)
# restores this real function for itself, layered on top of conftest's own per-test patch.
_REAL_REACHABLE_LOCAL_PROVIDER_IDS = main._reachable_local_provider_ids


# --- main._tojson_filter(): Jinja2Templates (Starlette) never registers Flask's own "tojson"
# filter, so this app registers one itself for the Reserve providers row-builder JS. Must tolerate
# Jinja's Undefined sentinel (a route rendering settings.html without every context key this page
# can reference leaves it here) without raising -- see test_wordlist_settings_routes.py's own
# regression test for the real incident this covers.


def test_tojson_filter_renders_real_data_as_valid_json():
    result = main._tojson_filter({"qwen": ["qwen-plus"]})
    assert json.loads(str(result)) == {"qwen": ["qwen-plus"]}


def test_tojson_filter_treats_undefined_as_null():
    result = main._tojson_filter(jinja2.Undefined())
    assert str(result) == "null"


def test_tojson_filter_escapes_html_breaking_characters():
    result = main._tojson_filter({"x": "</script><script>alert(1)"})
    assert "</script>" not in str(result)
    assert "<script>" not in str(result)


def _post_form(client, pairs):
    """TestClient/httpx's own `data=` kwarg doesn't accept a raw list of (key, value) tuples for
    repeated field names (confirmed live -- it raises trying to treat the list as byte content
    instead) -- urlencoding the pairs directly and posting as `content=` is the reliable way to
    submit several same-named "chain_provider"/"chain_model" fields, exactly what the real
    browser-submitted form (settings.html's multiple dropdown rows) sends."""
    return client.post("/api/settings/fallback-chain", content=urlencode(pairs), headers=_FORM_HEADERS, follow_redirects=False)


def test_fallback_chain_context_queries_only_referenced_providers_concurrently(monkeypatch):
    """Real, confirmed incident this fixes: each get_model_choices() call for a not-running local
    provider (LM Studio/Ollama), a custom endpoint, or Copilot is a genuine network round trip --
    under this project's own WSL2 networking, a single not-running local server alone took the full
    LOCAL_MODEL_DISCOVERY_TIMEOUT_SECONDS (~2s) to fail, landing on EVERY /settings load's own
    critical path even for an operator who has never touched the (off-by-default) fallback chain
    feature and runs no local LLM server at all -- a plain /settings load measured ~2s server-side
    purely from that. Only a provider actually already in use (the saved chain, or the current
    primary provider) is probed eagerly for its own MODEL LIST now; everything else is left for the
    row's own on-demand fetch (settings.html's populateModelSelect, via /api/settings/model-options)
    instead -- verified here by call count, not just wall-clock time, so a regression back to
    "probe everything eagerly" fails even if it happens to stay fast in this particular test run.

    conftest.py's own autouse fixture stubs out _reachable_local_provider_ids() (the SEPARATE,
    later-added reachability check for whether to even OFFER LM Studio/Ollama at all) to avoid a
    real network attempt on every test in the suite -- so this test's own get_model_choices mock is
    never actually reached for local providers at all, same as any other deferred provider."""
    provider_ids = [pid for pid, _ in main.all_provider_choices()]
    assert len(provider_ids) >= 2  # otherwise this test can't actually prove concurrency helped

    calls = []

    def slow_choices(pid):
        calls.append(pid)
        time.sleep(0.3)
        return [f"{pid}-model"]

    monkeypatch.setattr(main, "get_model_choices", slow_choices)

    start = time.monotonic()
    context = main._fallback_chain_context()
    elapsed = time.monotonic() - start

    deferred_ids = set(context["fallback_chain_deferred_provider_ids"])
    eager_ids = [pid for pid in provider_ids if pid not in deferred_ids]
    # This built-in registry always has at least local (LM Studio/Ollama) providers, so an empty
    # deferred set here would mean the deferral logic itself never kicked in -- a real regression,
    # not just a quiet environment.
    assert deferred_ids
    assert set(calls) == set(eager_ids)  # deferred providers were never probed at all

    assert elapsed < 0.3 * max(len(eager_ids), 1)  # concurrent, not summed -- the real regression
    assert elapsed < 1.5  # generous ceiling regardless of how many providers are configured
    for pid in eager_ids:
        assert context["fallback_chain_provider_model_choices"][pid] == [f"{pid}-model"]
    for pid in deferred_ids:
        assert context["fallback_chain_provider_model_choices"][pid] == []


def test_fallback_chain_context_still_eagerly_probes_a_deferred_provider_already_in_the_chain(monkeypatch):
    """A local/custom/Copilot provider that's actually IN the saved chain must still be probed
    eagerly -- otherwise its own row would render with an empty model dropdown, a real regression
    versus the pre-deferral behavior, just because it happens to be the deferrable kind."""
    from agent import settings
    settings.save_fallback_chain_settings(True, [{"provider": "lmstudio", "model": "local-model"}])

    calls = []
    monkeypatch.setattr(main, "get_model_choices", lambda pid: calls.append(pid) or [f"{pid}-model"])

    context = main._fallback_chain_context()
    assert "lmstudio" not in context["fallback_chain_deferred_provider_ids"]
    assert "lmstudio" in calls
    assert context["fallback_chain_provider_model_choices"]["lmstudio"] == ["lmstudio-model"]


def test_settings_page_renders_the_reserve_providers_section():
    client = TestClient(main.app)
    resp = client.get("/settings")
    assert resp.status_code == 200
    assert "Reserve providers" in resp.text
    assert "Enable custom fallback chain" in resp.text
    assert 'id="fallback-chain-rows"' in resp.text
    assert 'id="fallback-chain-add-row"' in resp.text


def _clear_all_provider_keys(monkeypatch):
    from agent.llm_client import PROVIDER_REGISTRY
    for config in PROVIDER_REGISTRY.values():
        monkeypatch.delenv(config.api_key_env, raising=False)


def test_fallback_chain_dropdown_excludes_an_unconfigured_provider_not_in_the_saved_chain(monkeypatch):
    """The picker for NEW rows must only offer providers actually usable right now -- an
    unconfigured one just gets silently skipped at scan time if picked (get_next_chain_step's own
    "not usable" tolerance), which looked like a real, working option to the operator."""
    _clear_all_provider_keys(monkeypatch)
    context = main._fallback_chain_context()
    assert "qwen" not in context["fallback_chain_provider_ids"]
    assert "opencode-zen" in context["fallback_chain_provider_ids"]  # never needs a key


def test_fallback_chain_dropdown_keeps_a_saved_but_now_unconfigured_provider_visible(monkeypatch):
    """Dropping a since-unconfigured provider from the OFFERED list must never make an
    already-saved row's own selection disappear -- only future picks are narrowed."""
    from agent import settings
    _clear_all_provider_keys(monkeypatch)
    settings.save_fallback_chain_settings(True, [{"provider": "qwen", "model": "qwen-plus"}])

    context = main._fallback_chain_context()
    assert "qwen" in context["fallback_chain_provider_ids"]
    assert context["fallback_chain_rows"][0]["provider"] == "qwen"


def test_fallback_chain_dropdown_includes_a_now_configured_provider(monkeypatch):
    _clear_all_provider_keys(monkeypatch)
    monkeypatch.setenv("QWEN_API_KEY", "sk-real-looking-key-123")
    context = main._fallback_chain_context()
    assert "qwen" in context["fallback_chain_provider_ids"]


def test_fallback_chain_dropdown_excludes_a_local_provider_that_is_not_reachable(monkeypatch):
    """conftest.py's own autouse fixture already stubs this to "nothing reachable" for every test
    -- this test just makes that behavior explicit and pins it down as a real regression guard."""
    monkeypatch.setattr(main, "_reachable_local_provider_ids", lambda: set())
    context = main._fallback_chain_context()
    assert "lmstudio" not in context["fallback_chain_provider_ids"]
    assert "ollama" not in context["fallback_chain_provider_ids"]


def test_fallback_chain_dropdown_includes_a_reachable_local_provider(monkeypatch):
    monkeypatch.setattr(main, "_reachable_local_provider_ids", lambda: {"lmstudio"})
    context = main._fallback_chain_context()
    assert "lmstudio" in context["fallback_chain_provider_ids"]
    assert "ollama" not in context["fallback_chain_provider_ids"]


def test_fallback_chain_dropdown_keeps_a_saved_but_now_unreachable_local_provider_visible(monkeypatch):
    """Same 'never silently hide an already-made selection' rule as an unconfigured cloud
    provider -- a local server that was running when the chain was saved and got stopped since
    must not make that row's own selection disappear, only future picks are narrowed."""
    from agent import settings
    monkeypatch.setattr(main, "_reachable_local_provider_ids", lambda: set())
    settings.save_fallback_chain_settings(True, [{"provider": "lmstudio", "model": "local-model"}])

    context = main._fallback_chain_context()
    assert "lmstudio" in context["fallback_chain_provider_ids"]
    assert context["fallback_chain_rows"][0]["provider"] == "lmstudio"


def test_reachable_local_provider_ids_queries_get_model_choices_concurrently(monkeypatch):
    monkeypatch.setattr(main, "_reachable_local_provider_ids", _REAL_REACHABLE_LOCAL_PROVIDER_IDS)
    calls = []

    def slow_choices(pid):
        calls.append(pid)
        time.sleep(0.3)
        return [f"{pid}-model"] if pid == "lmstudio" else []

    monkeypatch.setattr(main, "get_model_choices", slow_choices)

    start = time.monotonic()
    reachable = main._reachable_local_provider_ids()
    elapsed = time.monotonic() - start

    assert reachable == {"lmstudio"}
    assert set(calls) == {"lmstudio", "ollama"}
    assert elapsed < 0.5  # concurrent, not summed (2 * 0.3s serially would be >= 0.6s)


def test_settings_page_embeds_real_provider_model_choices_as_json():
    client = TestClient(main.app)
    resp = client.get("/settings")
    assert resp.status_code == 200
    # The add-row JS reads this <script type="application/json"> tag directly -- every known
    # provider id must have an (even if empty) entry, not just whichever one happens to be current.
    assert 'id="fallback-chain-provider-models"' in resp.text
    assert '"opencode-zen"' in resp.text
    assert '"qwen"' in resp.text


def test_settings_page_shows_the_disabled_state_by_default():
    client = TestClient(main.app)
    resp = client.get("/settings")
    assert resp.status_code == 200
    checkbox_tag = re.search(r'<input type="checkbox" name="enabled"[^>]*>', resp.text)
    assert checkbox_tag is not None
    assert "checked" not in checkbox_tag.group(0)


def test_save_fallback_chain_persists_multiple_ordered_rows_and_redisplays(monkeypatch):
    client = TestClient(main.app)
    monkeypatch.setenv("QWEN_API_KEY", "test-key")
    monkeypatch.setenv("MISTRAL_API_KEY", "test-key")

    resp = _post_form(client, [
        ("enabled", "on"),
        ("chain_provider", "qwen"), ("chain_model", "qwen-plus"),
        ("chain_provider", "qwen"), ("chain_model", "qwen-turbo"),
        ("chain_provider", "mistral"), ("chain_model", "mistral-small-latest"),
    ])
    assert resp.status_code == 303

    from agent import settings
    saved = settings.load_llm_settings()
    assert saved["fallback_chain_enabled"] is True
    assert saved["fallback_chain"] == [
        {"provider": "qwen", "model": "qwen-plus"},
        {"provider": "qwen", "model": "qwen-turbo"},
        {"provider": "mistral", "model": "mistral-small-latest"},
    ]

    page = client.get("/settings")
    assert page.text.count("data-fallback-chain-row") >= 3  # 3 real rows (plus the JS's own references to the attribute name)
    checkbox_tag = re.search(r'<input type="checkbox" name="enabled"[^>]*>', page.text)
    assert "checked" in checkbox_tag.group(0)


def test_save_fallback_chain_disabled_needs_no_rows():
    client = TestClient(main.app)
    resp = _post_form(client, [])
    assert resp.status_code == 303

    from agent import settings
    saved = settings.load_llm_settings()
    assert saved["fallback_chain_enabled"] is False
    assert saved["fallback_chain"] == []


def test_save_fallback_chain_skips_a_row_with_a_blank_model():
    client = TestClient(main.app)
    resp = _post_form(client, [("chain_provider", "qwen"), ("chain_model", "")])
    assert resp.status_code == 303

    from agent import settings
    assert settings.load_llm_settings()["fallback_chain"] == []


def test_save_fallback_chain_rejects_an_unknown_provider_id():
    client = TestClient(main.app)
    resp = _post_form(client, [("chain_provider", "totally-not-a-real-provider"), ("chain_model", "some-model")])
    assert resp.status_code == 400
    assert "Unknown provider id" in resp.text
