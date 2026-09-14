"""Global test isolation.

Every real module in this codebase does `logger = get_logger(CATEGORY)` at import time (see
agent/core.py, sessions/store.py, agent/llm_client.py, ...), and get_logger() permanently locks in
that logger's handlers on its *first* call (agent/utils/logger.py's `_configured` cache never
reconfigures a category once set). Pytest imports every test module -- and everything those modules
import -- during collection, which runs before any fixture (autouse or not) gets a chance to run.
By the time a fixture could flip DEBUG off, most loggers have already been configured against
whatever was live at that instant: the real .env's DEBUG=true (agent/__init__.py's load_dotenv()
runs at that same import time) and the real Documents/ASRA/debug.log -- exactly the file the run.bat
debug console tails live. A per-test fixture cannot undo that; only being set before collection
starts can. Plain module-level code here runs the moment pytest imports this conftest.py, which
happens before it imports any test module in this directory -- the earliest available hook.
load_dotenv() defaults to never overriding an already-set env var, so setting DEBUG here first is
enough to make the real .env's DEBUG=true a no-op for the whole test process.

sessions/store.py's SESSIONS_DIR/INDEX_PATH/SUMMARY_INDEX_PATH and the PROJECTS_DIR env var have
the identical problem for session storage: unisolated tests (e.g. test_wildcard_scope.py, which
builds session dicts by hand and drives _run_recon() directly) write real JSON into this repo's own
data/sessions/ -- confirmed after the fact by four stray usr_recon_*.json files sitting there (and,
separately, a real data/sessions_summary.json once SUMMARY_INDEX_PATH existed and this fixture
hadn't yet been updated to isolate it). Isolating these below, in the same fixture, closes that at
the same root: before any test-specific code runs.

agent/llm_client.py's _ENV_PATH has the identical problem for the real .env: a test that exercises
a Settings route end-to-end (TestClient, not a monkeypatched save_provider_api_key/base_url) writes
straight through to the developer's own .env via set_key/unset_key. Real incident this fixture
entry exists because of: adding a base_url field to /api/settings/api-key made that route also call
save_provider_base_url() unconditionally, and an existing test that only mocked
main.save_provider_api_key (not the new base_url call) let the real, unmocked function run --
deleting OPENCODE_ZEN_BASE_URL from the real .env on a routine test run, caught only by manually
diffing the file afterward. Tests that specifically verify _ENV_PATH's own read/write/read-back
behavior (test_api_key_management.py) already set their own explicit path per test, which simply
overrides this default within that test -- no conflict either way.

agent/settings.py's SETTINGS_PATH (data/llm_settings.json -- provider/model choice, the Reserve
providers fallback chain) has the same leak class too: test_settings.py already isolates it with
its own local fixture for the functions it tests directly, but that only covers that one file --
any OTHER test exercising a Settings route end-to-end (e.g. POST /api/settings/fallback-chain via
TestClient) would otherwise write straight through to this repo's own real data/llm_settings.json.
Isolated here in the same fixture, same reasoning as SESSIONS_DIR/WORDLIST_STORE_PATH above, so
every test gets it for free regardless of which file happens to exercise a Settings route first.

agent/custom_providers.py's CUSTOM_PROVIDERS_PATH (data/custom_providers.json -- operator-named
custom LLM provider instances, each carrying a real API key) is the identical leak class, isolated
here in the same turn it was introduced rather than left for a future test run to discover the hard
way (this repo's own history already has one incident each for SESSIONS_DIR and SUMMARY_INDEX_PATH
exactly like this). Patching the module's own global is enough even though agent/llm_client.py
imports these functions by name (`from agent.custom_providers import load_custom_providers, ...`)
-- a Python function's own free variables always resolve against the module it was DEFINED in, not
wherever it's later imported into, so one patch here covers every caller.

agent/codex_oauth.py's CODEX_TOKENS_PATH (data/codex_oauth_tokens.json -- the "Sign in with
ChatGPT" OAuth session, a real refresh token once anyone actually signs in on the machine running
these tests) is the same leak class again, isolated in the same turn it was introduced.

agent/tools/chat_settings_store.py's CHAT_SETTINGS_STORE_PATH (data/chat_settings.json -- the chat
panel's web_fetch/browser/subagent toggles, plus the operator's own last explicitly-picked chat
provider/model) is the same leak class again: agent/chat.py's _new_thread() now reads this file
unconditionally on every brand-new thread, so an unisolated test would both leak the real operator's
last-picked provider into thread-shape assertions AND (via save_chat_settings/save_last_chat_llm)
overwrite that operator's real toggles/pick with whatever a test happened to save.

TOOLKIT_ENABLED (agent/tools/toolkit_proxy.py, default "true") is a different flavor of the same
problem: agent/tools/browser_manager.py's get_or_create_context() now calls
get_toolkit_proxy_manager().ensure_started() unconditionally on every call, and unlike everything
above this doesn't just risk touching a real FILE -- left at its default, any test exercising
get_or_create_context() without explicitly mocking the toolkit proxy manager would bind a REAL
mitmproxy instance to a real TCP port for the rest of the test process's life (confirmed live: an
existing, unrelated stealth-user-agent test did exactly this the first time toolkit_proxy.py's
import was added, visible only as unexplained mitmproxy deprecation warnings under that test's own
name). Forced false here, same "module-level default so every test starts already isolated"
posture as DEBUG above -- tests/test_toolkit_proxy.py's own tests override it back per-test via
monkeypatch to exercise the enabled path, same as every other explicit-override test in this file.

agent/core.py's own in-memory, keyed-by-session_id dicts (_stop_events, _approval_events,
_re_stop_intent, _instruction_queues, _exhausted_chain_steps, _claimed_chain_steps) are the same
leak class again, module-global and never cleared between tests. Real incident this entry exists
because of: multiple tests across tests/test_chain_pass.py, tests/test_reverify_phase.py,
tests/test_skeptical_verification_pass.py and tests/test_hypothesis_gate.py all build a RunContext
with the same hardcoded session_id (e.g. "usr_chain_test") -- once _dispatch_tool_interruptible
(agent/core.py) started actually consuming get_stop_event() mid-tool-call instead of it being
inert dead weight there, an asyncio.Event left set() by an earlier test using that same literal id
made every later test sharing it raise SessionStopRequested immediately, well before any of it
touched Stop-button behavior at all. Cleared here, not per-test-file, so every test starts with a
clean slate regardless of which one happens to touch this state first.
"""
import os
import tempfile

os.environ["DEBUG"] = "false"
os.environ["APP_DATA_DIR"] = tempfile.mkdtemp(prefix="asra-test-app-dir-")
os.environ["TOOLKIT_ENABLED"] = "false"

import pytest


@pytest.fixture(autouse=True)
def _never_touch_real_app_state(tmp_path, monkeypatch):
    """Per-test backstop on top of the module-level guard above -- gives each test its own throwaway
    dirs (rather than sharing the one process-wide tmp dir from module load) and covers a test that
    monkeypatches env vars back to something real by mistake. A test that wants to exercise actual
    DEBUG=true behavior must still reset agent.utils.logger's `_configured` cache and clear the
    relevant logger's handlers itself, same as tests/test_debug_module.py already does for "UI" --
    the module-level guard above means every category starts this process already locked onto a
    NullHandler, same as if DEBUG had always been false.
    """
    monkeypatch.setenv("DEBUG", "false")
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path / "asra-app-dir"))
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "asra-projects-dir"))
    monkeypatch.setenv("TOOLKIT_ENABLED", "false")

    import agent.core as core_mod
    import projects.paths as paths_mod
    import sessions.store as store_mod
    import agent.llm_client as llm_client_mod
    import agent.settings as settings_mod
    import agent.custom_providers as custom_providers_mod
    import agent.codex_oauth as codex_oauth_mod
    import agent.copilot_oauth as copilot_oauth_mod
    import agent.tools.wordlist_store as wordlist_store_mod
    import agent.tools.subagent_store as subagent_store_mod
    import agent.tools.chat_settings_store as chat_settings_store_mod
    import agent.tools.toolkit_settings_store as toolkit_settings_store_mod

    paths_mod.resolve_global_app_dir.cache_clear()
    paths_mod.resolve_projects_base_dir.cache_clear()
    monkeypatch.setattr(store_mod, "SESSIONS_DIR", tmp_path / "asra-sessions-dir")
    monkeypatch.setattr(store_mod, "INDEX_PATH", tmp_path / "asra-sessions-dir" / "sessions_index.json")
    monkeypatch.setattr(store_mod, "SUMMARY_INDEX_PATH", tmp_path / "asra-sessions-dir" / "sessions_summary.json")
    monkeypatch.setattr(llm_client_mod, "_ENV_PATH", str(tmp_path / "asra-test.env"))
    monkeypatch.setattr(settings_mod, "SETTINGS_PATH", tmp_path / "asra-llm-settings.json")
    monkeypatch.setattr(custom_providers_mod, "CUSTOM_PROVIDERS_PATH", tmp_path / "asra-custom-providers.json")
    monkeypatch.setattr(codex_oauth_mod, "CODEX_TOKENS_PATH", tmp_path / "asra-codex-oauth-tokens.json")
    monkeypatch.setattr(copilot_oauth_mod, "COPILOT_TOKENS_PATH", tmp_path / "asra-copilot-oauth-tokens.json")
    # Real incident this closes: ffuf/arjun/hydra/web_login_bruteforce builders all consult
    # get_assigned_wordlist() unconditionally now -- an operator's own real Settings-UI wordlist
    # assignment on the machine running these tests (data/wordlist_assignments.json) would
    # otherwise silently override whatever wordlist a "uses the default when none given"-shaped
    # test asserts on, exactly the SESSIONS_DIR/INDEX_PATH leak this same fixture already guards.
    monkeypatch.setattr(wordlist_store_mod, "WORDLIST_STORE_PATH", tmp_path / "asra-wordlist-assignments.json")
    # Same leak class, same fix: a future phase's tool_specs helper consults get_enabled_profiles()
    # unconditionally, so an operator's own real Subagents profiles on the machine running these
    # tests would otherwise leak into any test asserting on a session's own available tool list.
    monkeypatch.setattr(subagent_store_mod, "SUBAGENT_STORE_PATH", tmp_path / "asra-subagent-profiles.json")
    monkeypatch.setattr(chat_settings_store_mod, "CHAT_SETTINGS_STORE_PATH", tmp_path / "asra-chat-settings.json")
    # Same leak class, same fix: agent/chat.py's _chat_tool_specs() and agent/core.py's
    # _toolkit_tool_extras()/_delegate_to_subagent_impl all consult load_toolkit_agent_settings()
    # unconditionally -- an operator's own real data/toolkit_agent_settings.json (this project's own
    # real one has every toggle enabled) would otherwise leak real toolkit tools into any test
    # asserting on a chat/phase/subagent tool list, exactly what surfaced as three real, spuriously
    # failing tests in tests/test_chat.py the moment that real file gained its 6th key (Sequencer).
    monkeypatch.setattr(toolkit_settings_store_mod, "TOOLKIT_AGENT_SETTINGS_STORE_PATH", tmp_path / "asra-toolkit-agent-settings.json")
    # Real incident this closes: main.py's _fallback_chain_context/_secondary_verification_context
    # both added a real, live reachability probe for LM Studio/Ollama (_reachable_local_provider_ids)
    # so an unstarted local server no longer looks like a pickable, configured provider in Settings.
    # Left unmocked, every one of the 9+ test files that ever hit GET /settings would make a real
    # network attempt to localhost:1234/localhost:11434 on this machine, on every single test --
    # harmless when nothing's listening there (near-instant refusal) but genuinely slow/hanging if
    # something ever IS listening on either port during a test run, and non-deterministic either
    # way. Defaults to "neither is reachable" (empty set) for every test; a test that specifically
    # wants to exercise the "IS reachable" branch overrides this itself, same as any other mock.
    import main as main_mod
    monkeypatch.setattr(main_mod, "_reachable_local_provider_ids", lambda: set())
    core_mod._stop_events.clear()
    core_mod._approval_events.clear()
    core_mod._re_stop_intent.clear()
    core_mod._instruction_queues.clear()
    core_mod._exhausted_chain_steps.clear()
    core_mod._claimed_chain_steps.clear()

    yield

    paths_mod.resolve_global_app_dir.cache_clear()
    paths_mod.resolve_projects_base_dir.cache_clear()
    core_mod._stop_events.clear()
    core_mod._approval_events.clear()
    core_mod._re_stop_intent.clear()
    core_mod._instruction_queues.clear()
    core_mod._exhausted_chain_steps.clear()
    core_mod._claimed_chain_steps.clear()
