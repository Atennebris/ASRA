"""list_models(): per-provider model list for the Settings model dropdown."""
from unittest.mock import patch

import agent.providers.models_dev as models_dev
from agent.providers.models_dev import is_model_free, list_models


def _reset_catalog_memo(monkeypatch):
    """_fetch_catalog's own in-process memo (module-level globals) must never leak between tests --
    each test gets a clean "nothing memoized yet" starting point, same isolation every other
    module-level cache in this project's tests already gets."""
    monkeypatch.setattr(models_dev, "_catalog_memo", None)
    monkeypatch.setattr(models_dev, "_catalog_memo_at", 0.0)


def test_fetch_catalog_memoizes_in_process_within_the_ttl_window(monkeypatch):
    """Real, confirmed incident this fixes: every _fetch_catalog() call re-read and re-parsed the
    whole on-disk cache file (a real ~4.9 MB JSON document) even when the in-process memo could
    have answered instantly -- measured at ~2-4s combined across a single /dashboard load (134
    real sessions, two functions each calling get_model_cost() once per session). Calling
    _fetch_catalog() twice in a row must hit the on-disk cache_get() at most ONCE."""
    _reset_catalog_memo(monkeypatch)
    catalog = {"opencode": {"models": {"big-pickle": {}}}}
    calls = []

    def _fake_cache_get(tool_name, query, ttl_seconds=None):
        calls.append((tool_name, query))
        return catalog

    monkeypatch.setattr(models_dev, "cache_get", _fake_cache_get)

    first = models_dev._fetch_catalog()
    second = models_dev._fetch_catalog()

    assert first == catalog
    assert second == catalog
    assert len(calls) == 1


def test_fetch_catalog_re_reads_once_the_memo_expires(monkeypatch):
    _reset_catalog_memo(monkeypatch)
    catalog = {"opencode": {"models": {"big-pickle": {}}}}
    calls = []
    monkeypatch.setattr(models_dev, "cache_get", lambda *a, **k: calls.append(1) or catalog)
    monkeypatch.setenv("MODELS_DEV_CACHE_TTL_SECONDS", "1")

    models_dev._fetch_catalog()
    # Simulate the memo having been set a while ago, past the (now 1-second) TTL.
    monkeypatch.setattr(models_dev, "_catalog_memo_at", 0.0)
    models_dev._fetch_catalog()

    assert len(calls) == 2


def test_list_models_returns_sorted_ids_for_known_provider():
    catalog = {"opencode": {"models": {"big-pickle": {}, "another-model": {}}}}
    with patch("agent.providers.models_dev._fetch_catalog", return_value=catalog):
        assert list_models("opencode") == ["another-model", "big-pickle"]


def test_list_models_returns_empty_list_for_unknown_provider():
    catalog = {"opencode": {"models": {"big-pickle": {}}}}
    with patch("agent.providers.models_dev._fetch_catalog", return_value=catalog):
        assert list_models("nonexistent-provider") == []


def test_list_models_returns_empty_list_when_catalog_unreachable():
    with patch("agent.providers.models_dev._fetch_catalog", return_value=None):
        assert list_models("opencode") == []


def test_is_model_free_true_when_cost_is_exactly_zero():
    with patch("agent.providers.models_dev.get_model_cost", return_value={"input": 0, "output": 0}):
        assert is_model_free("opencode", "big-pickle") is True


def test_is_model_free_false_when_cost_is_nonzero():
    with patch("agent.providers.models_dev.get_model_cost", return_value={"input": 0.15, "output": 0.6}):
        assert is_model_free("mistral", "mistral-small-latest") is False


def test_is_model_free_false_when_only_one_side_is_zero():
    """A model priced at $0 input but real $ output (or vice versa) is not actually free -- both
    sides must be zero, same "input==0 and output==0" derivation this project's own sibling
    dashboard app already uses for its own opencode-local catalog."""
    with patch("agent.providers.models_dev.get_model_cost", return_value={"input": 0, "output": 2.0}):
        assert is_model_free("some-provider", "some-model") is False


def test_is_model_free_none_when_cost_is_unknown():
    """None (unknown), never False -- get_model_cost returning None means "the catalog doesn't
    know", not "confirmed paid"; callers (main.py's _model_free_flags) must not treat this as a
    reason to hide the model from a "Free models only" filter."""
    with patch("agent.providers.models_dev.get_model_cost", return_value=None):
        assert is_model_free("unknown-provider", "unknown-model") is None
