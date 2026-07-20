"""list_models(): per-provider model list for the Settings model dropdown."""
from unittest.mock import patch

from agent.providers.models_dev import list_models


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
