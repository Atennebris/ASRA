"""Cross-session asset baseline: agent/tools/asset_baseline_store.py's persistence
(load_asset_baseline_store/diff_and_update) and the asset_diff_check native tool wrapper.

A first scan of a (target, category) pair seeds the baseline with no diff (nothing to compare
against yet); every scan after that reports what's genuinely new/removed since the LAST scan of
that same target+category, and replaces the stored list wholesale each time.
"""
import json

from agent.tools import asset_baseline_store
from agent.tools.asset_baseline_store import (
    asset_diff_check,
    diff_and_update,
    load_asset_baseline_store,
)


def _isolate_store(tmp_path, monkeypatch):
    monkeypatch.setattr(asset_baseline_store, "ASSET_BASELINE_STORE_PATH", tmp_path / "assets.json")


# --- asset_baseline_store: persistence -----------------------------------------------------------


def test_load_returns_empty_dict_when_file_missing(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    assert load_asset_baseline_store() == {}


def test_load_returns_empty_dict_on_corrupt_json(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    asset_baseline_store.ASSET_BASELINE_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    asset_baseline_store.ASSET_BASELINE_STORE_PATH.write_text("{not valid json", encoding="utf-8")
    assert load_asset_baseline_store() == {}


def test_load_filters_out_malformed_entries(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    asset_baseline_store.ASSET_BASELINE_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    asset_baseline_store.ASSET_BASELINE_STORE_PATH.write_text(
        json.dumps({"example.com": {"subdomains": {"assets": ["a"]}}, "bad_key": "not-a-dict", "123": ["also-bad"]}),
        encoding="utf-8",
    )
    store = load_asset_baseline_store()
    assert "example.com" in store
    assert "bad_key" not in store


# --- diff_and_update: the core diff logic --------------------------------------------------------


def test_first_scan_reports_no_new_or_removed_assets(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    result = diff_and_update("example.com", "subdomains", ["api.example.com", "www.example.com"])

    assert result["first_scan"] is True
    assert result["new_assets"] == []
    assert result["removed_assets"] == []
    assert result["total_known_assets"] == 2


def test_second_scan_surfaces_newly_added_assets(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    diff_and_update("example.com", "subdomains", ["api.example.com", "www.example.com"])

    result = diff_and_update("example.com", "subdomains", ["api.example.com", "www.example.com", "staging.example.com"])

    assert result["first_scan"] is False
    assert result["new_assets"] == ["staging.example.com"]
    assert result["removed_assets"] == []
    assert result["total_known_assets"] == 3


def test_second_scan_surfaces_removed_assets(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    diff_and_update("example.com", "subdomains", ["api.example.com", "old.example.com"])

    result = diff_and_update("example.com", "subdomains", ["api.example.com"])

    assert result["removed_assets"] == ["old.example.com"]
    assert result["new_assets"] == []


def test_categories_for_the_same_target_are_diffed_independently(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    diff_and_update("example.com", "subdomains", ["api.example.com"])

    # A first scan of a DIFFERENT category under the same target is still its own first scan.
    result = diff_and_update("example.com", "open_ports", ["example.com:443/https"])

    assert result["first_scan"] is True


def test_duplicate_and_blank_assets_are_deduped_and_stripped(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    diff_and_update("example.com", "subdomains", ["api.example.com", "api.example.com", "  ", ""])

    result = diff_and_update("example.com", "subdomains", ["api.example.com"])

    assert result["total_known_assets"] == 1
    assert result["new_assets"] == []


def test_stored_baseline_survives_a_reload(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    diff_and_update("example.com", "subdomains", ["api.example.com"])

    store = load_asset_baseline_store()
    assert store["example.com"]["subdomains"]["assets"] == ["api.example.com"]
    assert "first_seen" in store["example.com"]["subdomains"]
    assert "last_updated" in store["example.com"]["subdomains"]


# --- asset_diff_check: the LLM-facing tool wrapper -------------------------------------------------


def test_asset_diff_check_happy_path(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    result = asset_diff_check({"target": "example.com", "category": "subdomains", "current_assets": ["api.example.com"]})

    assert result["status"] == "ok"
    assert result["first_scan"] is True


def test_asset_diff_check_returns_disabled_when_toggled_off(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    monkeypatch.setenv("ASSET_BASELINE_ENABLED", "false")

    result = asset_diff_check({"target": "example.com", "category": "subdomains", "current_assets": ["api.example.com"]})

    assert result == {"status": "disabled"}
    assert load_asset_baseline_store() == {}  # disabled means no read/write happened at all


def test_asset_diff_check_rejects_a_non_list_current_assets(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    result = asset_diff_check({"target": "example.com", "category": "subdomains", "current_assets": "not-a-list"})

    assert result["status"] == "error"
