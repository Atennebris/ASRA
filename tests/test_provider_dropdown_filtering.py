"""Settings' AI Provider & Model picker must list ONLY the providers the operator actually added --
the same subset the "// Providers" list below it shows -- not every built-in in PROVIDER_REGISTRY.

Real, confirmed incident: the top provider dropdown iterated the cloud_provider_ids/local_provider_ids
template globals (the whole registry) unconditionally, so with only four providers added the picker
still offered all ~18 built-ins as if every one were configured, flatly contradicting the Providers
list right beside it. _llm_settings_context now derives added_cloud_provider_ids/added_local_provider_ids
from the same provider_added logic that list uses.
"""
import main
from agent.llm_client import PROVIDER_REGISTRY


def _only_added(monkeypatch, added_ids, current="opencode-zen"):
    """Isolate _llm_settings_context so 'what counts as added' is exactly `added_ids` (plus whatever
    is self-evidently in use -- here just `current`, selected but keyless)."""
    monkeypatch.setattr(main, "load_llm_settings", lambda: {"provider": current})
    monkeypatch.setattr(main, "get_added_providers", lambda: list(added_ids))
    monkeypatch.setattr(main, "get_provider_api_key", lambda cfg: "")
    monkeypatch.setattr(main, "get_model_choices", lambda pid: [])
    monkeypatch.setattr(main, "all_provider_choices", lambda: [])
    # No base-url overrides in play -- make provider_added depend only on added-list + current.
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    for cfg in PROVIDER_REGISTRY.values():
        monkeypatch.delenv(cfg.base_url_env, raising=False)


def test_dropdown_lists_only_added_cloud_providers_not_the_whole_registry(monkeypatch):
    _only_added(monkeypatch, added_ids=["qwen", "mistral", "openrouter"], current="opencode-zen")
    ctx = main._llm_settings_context()
    cloud = ctx["added_cloud_provider_ids"]
    # The four the operator has (three added + the selected opencode-zen) show up...
    for pid in ("opencode-zen", "qwen", "mistral", "openrouter"):
        assert pid in cloud
    # ...and a built-in that was never added and has no key does NOT.
    assert "openai" not in cloud
    assert "anthropic" not in cloud


def test_the_active_provider_is_always_listed_even_if_not_explicitly_added(monkeypatch):
    """provider_added folds in the currently-selected provider, so the picker can never filter out
    the very choice that's active -- it would otherwise render a dropdown with the saved value
    missing from its own options."""
    _only_added(monkeypatch, added_ids=[], current="deepseek")
    ctx = main._llm_settings_context()
    assert "deepseek" in ctx["added_cloud_provider_ids"]


def test_no_local_provider_added_yields_an_empty_local_list(monkeypatch):
    """The template hides an empty <optgroup> entirely; this is the data half of that -- with no
    local provider added, the Local list is empty rather than every local built-in. opencode-local
    (agent/opencode_local_provider.py) is gated by the exact same "actually added, or it's the
    active choice" rule as every PROVIDER_REGISTRY local provider -- real, confirmed operator
    complaint an earlier version of this got wrong: it used to show up here unconditionally, with
    no way to add/remove it from the "// Providers" list at all, breaking the "I control what
    shows up by adding it myself" expectation every other provider already gives."""
    _only_added(monkeypatch, added_ids=["qwen"], current="opencode-zen")
    ctx = main._llm_settings_context()
    assert ctx["added_local_provider_ids"] == []


def test_opencode_local_appears_once_explicitly_added(monkeypatch):
    _only_added(monkeypatch, added_ids=["qwen", "opencode-local"], current="opencode-zen")
    ctx = main._llm_settings_context()
    assert ctx["added_local_provider_ids"] == ["opencode-local"]


def test_opencode_local_is_always_listed_when_it_is_the_active_provider(monkeypatch):
    _only_added(monkeypatch, added_ids=[], current="opencode-local")
    ctx = main._llm_settings_context()
    assert ctx["added_local_provider_ids"] == ["opencode-local"]
