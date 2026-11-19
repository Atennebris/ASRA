"""Unit tests for the weak-model quality signal (agent/core.py): the sliding-window invalid-rate
that warns the operator once per phase when a model keeps emitting invalid tool calls, its env
gating, and the shared argument-coercion helper now used at every dispatch site (including the
forced-final/terminal-repair path, which previously bypassed coercion).
"""
from types import SimpleNamespace

import agent.core as core

_SCHEMA = {"type": "object", "properties": {"port": {"type": "integer"}, "host": {"type": "string"}}}


def _fake_call(name="probe", arguments=None):
    return SimpleNamespace(name=name, arguments=arguments if arguments is not None else {})


def _fake_spec(name="probe", schema=None):
    return SimpleNamespace(name=name, parameters_schema=schema)


def _fake_ctx():
    return SimpleNamespace(session_id="sess-test")


# --- _coerce_call_args: the shared helper every dispatch site now routes through -------------------

def test_coerce_call_args_coerces_when_enabled(monkeypatch):
    monkeypatch.delenv("TOOL_ARG_COERCION", raising=False)  # default on
    call = _fake_call(arguments={"port": "8080"})
    out = core._coerce_call_args(_fake_ctx(), "recon", call, _fake_spec(schema=_SCHEMA))
    assert out["port"] == 8080 and isinstance(out["port"], int)
    # Original call object is never mutated -- only the returned dict carries the fix.
    assert call.arguments["port"] == "8080"


def test_coerce_call_args_passthrough_when_spec_is_none(monkeypatch):
    monkeypatch.delenv("TOOL_ARG_COERCION", raising=False)
    call = _fake_call(arguments={"port": "8080"})
    out = core._coerce_call_args(_fake_ctx(), "recon", call, None)
    assert out is call.arguments  # unknown tool -> no schema -> untouched


def test_coerce_call_args_disabled_by_flag(monkeypatch):
    monkeypatch.setenv("TOOL_ARG_COERCION", "false")
    call = _fake_call(arguments={"port": "8080"})
    out = core._coerce_call_args(_fake_ctx(), "recon", call, _fake_spec(schema=_SCHEMA))
    assert out == {"port": "8080"}  # left exactly as the model sent it


# --- _weak_signal_update: sliding-window invalid rate ---------------------------------------------

def test_weak_signal_none_until_window_full():
    window: list[bool] = []
    assert core._weak_signal_update(window, True, 3) is None
    assert core._weak_signal_update(window, True, 3) is None
    assert core._weak_signal_update(window, True, 3) == 1.0  # full now


def test_weak_signal_rate_is_the_fraction_invalid():
    window: list[bool] = []
    core._weak_signal_update(window, True, 4)
    core._weak_signal_update(window, False, 4)
    core._weak_signal_update(window, True, 4)
    assert core._weak_signal_update(window, False, 4) == 0.5  # 2 of 4


def test_weak_signal_window_slides_and_stays_capped():
    window: list[bool] = []
    for _ in range(3):
        core._weak_signal_update(window, True, 3)  # window = [T, T, T]
    # Three good calls in a row push the bad ones out: rate should fall to 0.
    core._weak_signal_update(window, False, 3)
    core._weak_signal_update(window, False, 3)
    rate = core._weak_signal_update(window, False, 3)
    assert rate == 0.0 and len(window) == 3


def test_weak_signal_trips_only_above_threshold():
    # 7 invalid of 10 -> 0.7, above the 0.6 default -> would warn.
    window = [True] * 7 + [False] * 3
    assert sum(window) / len(window) >= core._DEFAULT_WEAK_SIGNAL_INVALID_RATE
    # 4 invalid of 10 -> 0.4, below -> would not warn.
    window = [True] * 4 + [False] * 6
    assert sum(window) / len(window) < core._DEFAULT_WEAK_SIGNAL_INVALID_RATE


# --- env gating -----------------------------------------------------------------------------------

def test_weak_signal_enabled_default_and_off(monkeypatch):
    monkeypatch.delenv("WEAK_SIGNAL_ENABLED", raising=False)
    assert core._weak_signal_enabled() is True
    monkeypatch.setenv("WEAK_SIGNAL_ENABLED", "false")
    assert core._weak_signal_enabled() is False


def test_weak_signal_window_env(monkeypatch):
    monkeypatch.delenv("WEAK_SIGNAL_WINDOW", raising=False)
    assert core._weak_signal_window() == core._DEFAULT_WEAK_SIGNAL_WINDOW
    monkeypatch.setenv("WEAK_SIGNAL_WINDOW", "25")
    assert core._weak_signal_window() == 25
    monkeypatch.setenv("WEAK_SIGNAL_WINDOW", "garbage")
    assert core._weak_signal_window() == core._DEFAULT_WEAK_SIGNAL_WINDOW


def test_weak_signal_invalid_rate_env(monkeypatch):
    monkeypatch.delenv("WEAK_SIGNAL_INVALID_RATE", raising=False)
    assert core._weak_signal_invalid_rate() == core._DEFAULT_WEAK_SIGNAL_INVALID_RATE
    monkeypatch.setenv("WEAK_SIGNAL_INVALID_RATE", "0.8")
    assert core._weak_signal_invalid_rate() == 0.8
    monkeypatch.setenv("WEAK_SIGNAL_INVALID_RATE", "5")  # out of (0,1] range
    assert core._weak_signal_invalid_rate() == core._DEFAULT_WEAK_SIGNAL_INVALID_RATE
    monkeypatch.setenv("WEAK_SIGNAL_INVALID_RATE", "nope")
    assert core._weak_signal_invalid_rate() == core._DEFAULT_WEAK_SIGNAL_INVALID_RATE


# --- live mechanism: the real tool loop must not re-log an unchanged rate on every call -----------


def test_invalid_tool_call_rate_log_line_is_not_repeated_when_the_rate_does_not_change(tmp_path, monkeypatch):
    """Real, confirmed incident this fixes (Telenor-Sweden-YesWeHack rescan session): this debug
    line printed on literally every real tool-call attempt once the sliding window filled -- 169
    identical lines across one hour-long recon, even though the rate stayed flat at a healthy 0%
    the entire time -- noise that reads like a retry loop to a human skimming debug.log. Drives
    the REAL _run_recon tool loop (not a mock of _weak_signal_update) with 10 genuinely valid,
    always-succeeding tool calls and counts the real logger.debug calls it produces.
    """
    import dataclasses

    import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
    from agent.core import RunContext, _run_recon
    from agent.llm_client import LLMResponse, ToolCallRequest
    from agent.tools.registry import TOOL_REGISTRY
    from sessions import store

    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("WEAK_SIGNAL_WINDOW", "2")  # fills fast -- a real number arrives quickly

    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == "dns_lookup")
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(
        original_spec, tool_tier=1, native_function=lambda params: {"status": "ok", "ips": ["1.2.3.4"]},
    )

    logged_rate_lines = []
    original_debug = core.logger.debug

    def _capture(msg, *args, **kwargs):
        if isinstance(msg, str) and "invalid tool-call rate" in msg:
            logged_rate_lines.append(args)
        return original_debug(msg, *args, **kwargs)

    monkeypatch.setattr(core.logger, "debug", _capture)

    class _AlwaysValidLLM:
        provider_id = "test-provider"
        model = "test-model"

        def __init__(self, n):
            self._script = [("dns_lookup", {"domain": f"h{i}.example.com"}) for i in range(n)]
            self.calls_made = 0

        def complete(self, messages, tools=None, stop_check=None):
            self.calls_made += 1
            if self._script:
                name, args = self._script.pop(0)
                return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"c{self.calls_made}", name=name, arguments=args)])
            return LLMResponse(content="done", tool_calls=[])

    try:
        session = {
            "session_id": "usr_rate_log_noise", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        }
        ctx = RunContext(llm=_AlwaysValidLLM(10), session=session, session_id=session["session_id"])

        asyncio_run = __import__("asyncio").run
        asyncio_run(_run_recon(ctx, "example.com"))

        # 10 always-valid calls, a window of 2 -- the rate becomes a real number (0%) starting at
        # call 2 and never changes again. Before this fix: one log line per call once the window
        # filled (9 lines). After: exactly one, the moment the rate first became known.
        assert len(logged_rate_lines) == 1
    finally:
        TOOL_REGISTRY[index] = original_spec
