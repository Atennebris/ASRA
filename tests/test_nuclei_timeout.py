"""ToolSpec.timeout_env_var/timeout_default_seconds -- a per-tool timeout override checked FIRST
by runner.py's _timeout_for, before the generic scan/exploit-category env var. Real, confirmed
incident this exists for (Live-Nation-HackerOne-usr_0f5c71): nuclei's default tag set did not
finish even once in 4/4 attempts at TOOL_TIMEOUT_SECONDS=600 against a real target -- a tool
whose own real-world duration doesn't fit the generic scan-category bucket deserves its own,
separate budget. Deliberately a generic ToolSpec field, not a hardcoded tool-name check inside
_timeout_for, so the next tool found to need its own budget plugs in the same way.
"""
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools.registry import ToolSpec, get_tool
from agent.tools.runner import _timeout_for


def _synthetic_spec(**overrides) -> ToolSpec:
    defaults = dict(
        name="synthetic_timeout_test_tool", category="scan", tool_tier=1, executable="",
        build_command=None, requires_allowed_target=False, installed_by_default=True,
        native_function=lambda p: {"status": "ok"},
    )
    defaults.update(overrides)
    return ToolSpec(**defaults)


def test_timeout_env_var_override_wins_over_the_category_default(monkeypatch):
    monkeypatch.setenv("SYNTHETIC_TOOL_TIMEOUT_SECONDS", "4242")
    spec = _synthetic_spec(timeout_env_var="SYNTHETIC_TOOL_TIMEOUT_SECONDS", timeout_default_seconds=120)
    assert _timeout_for(spec) == 4242


def test_timeout_env_var_override_falls_back_to_its_own_default_when_unset(monkeypatch):
    monkeypatch.delenv("SYNTHETIC_TOOL_TIMEOUT_SECONDS", raising=False)
    spec = _synthetic_spec(timeout_env_var="SYNTHETIC_TOOL_TIMEOUT_SECONDS", timeout_default_seconds=777)
    assert _timeout_for(spec) == 777


def test_a_tool_without_the_override_still_uses_the_old_category_based_behavior(monkeypatch):
    """Regression guard: every tool that never set timeout_env_var (the overwhelming majority)
    must keep behaving exactly as before this field existed."""
    monkeypatch.setenv("TOOL_TIMEOUT_SECONDS", "321")
    spec = _synthetic_spec()
    assert spec.timeout_env_var is None
    assert _timeout_for(spec) == 321


def test_nuclei_is_registered_with_its_own_timeout_override():
    spec = get_tool("nuclei")
    assert spec.timeout_env_var == "NUCLEI_TIMEOUT_SECONDS"
    assert spec.timeout_default_seconds == 1200


def test_nuclei_actually_honors_its_own_env_var(monkeypatch):
    monkeypatch.setenv("NUCLEI_TIMEOUT_SECONDS", "999")
    assert _timeout_for(get_tool("nuclei")) == 999


def test_nuclei_falls_back_to_its_own_default_when_the_env_var_is_unset(monkeypatch):
    monkeypatch.delenv("NUCLEI_TIMEOUT_SECONDS", raising=False)
    assert _timeout_for(get_tool("nuclei")) == 1200
